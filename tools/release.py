#!/usr/bin/env python3
"""Build public artifacts and publish a checked release; never handles signing keys."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPO = os.environ.get('GITHUB_REPOSITORY', 'bug0000/pingtun')
VERSION = (ROOT / 'VERSION').read_text().strip()
if not re.fullmatch(r'\d+\.\d+\.\d+', VERSION):
    raise SystemExit('A regular semantic version is required')


def api(path, data=None, method=None, content_type='application/json'):
    url = path if path.startswith('https://uploads.github.com/') else 'https://api.github.com' + path
    if not url.startswith(('https://api.github.com/', 'https://uploads.github.com/')):
        raise ValueError('Unexpected API destination')
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'pingtun-release',
               'X-GitHub-Api-Version': '2026-03-10'}
    if os.environ.get('GH_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
    if data is not None:
        if not isinstance(data, bytes):
            data = json.dumps(data, ensure_ascii=False).encode()
        headers['Content-Type'] = content_type
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=90) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise RuntimeError('GitHub API request failed: HTTP ' + str(error.code)) from None


def manifest():
    m = json.loads((ROOT / 'release-artifacts.json').read_text())
    assert m['version'] == VERSION
    for key in ['android_sha256', 'android_certificate_sha256', 'android_gzip_sha256']:
        assert re.fullmatch('[0-9a-f]{64}', m[key])
    assert 0 < m['android_size'] < 100_000_000 and 0 < m['android_gzip_size'] < 32_000_000
    assert 0 < len(m['android_gzip_blobs']) <= 128
    assert all(re.fullmatch('[0-9a-f]{40}', sha) for sha in m['android_gzip_blobs'])
    return m


def checked_sha():
    sha = os.environ['SOURCE_SHA']
    assert re.fullmatch('[0-9a-f]{40}', sha)
    return sha


def gate():
    sha = checked_sha()
    head = api('/repos/' + REPO + '/git/ref/heads/main')
    if not head or head['object']['sha'] != sha:
        return False
    existing = api('/repos/' + REPO + '/releases/tags/v' + VERSION)
    if existing and not existing['draft']:
        return False
    runs = api('/repos/' + REPO + '/actions/runs?per_page=100&head_sha=' + sha)['workflow_runs']
    for name in ['CI', 'Android']:
        candidates = [r for r in runs if r['name'] == name and r['head_sha'] == sha
                      and r['head_branch'] == 'main' and r['event'] == 'push']
        if not candidates:
            return False
        run = max(candidates, key=lambda r: r['id'])
        if run['status'] != 'completed' or run['conclusion'] != 'success':
            return False
    manifest()
    return True


def download_android(out):
    m = manifest()
    chunks = []
    for sha in m['android_gzip_blobs']:
        blob = api('/repos/' + REPO + '/git/blobs/' + sha)
        if not blob or blob['encoding'] != 'base64':
            raise RuntimeError('Missing signed APK payload')
        raw = base64.b64decode(''.join(blob['content'].split()), validate=True)
        assert len(raw) <= 262144
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == sha
        chunks.append(raw)
    packed = b''.join(chunks)
    assert len(packed) == m['android_gzip_size']
    assert hashlib.sha256(packed).hexdigest() == m['android_gzip_sha256']
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        apk = stream.read(m['android_size'] + 1)
    assert len(apk) == m['android_size'] and hashlib.sha256(apk).hexdigest() == m['android_sha256']
    out.mkdir(parents=True, exist_ok=True)
    target = out / ('pingtun_' + VERSION + '_android.apk')
    target.write_bytes(apk)
    return target


def verify_apk(out):
    apk = download_android(out)
    sdk = Path(os.environ.get('ANDROID_SDK_ROOT', os.environ.get('ANDROID_HOME', ''))) / 'build-tools/35.0.0'
    result = subprocess.check_output([str(sdk / 'apksigner'), 'verify', '--verbose', '--print-certs', str(apk)], text=True)
    expected = 'Signer #1 certificate SHA-256 digest: ' + manifest()['android_certificate_sha256']
    assert expected in result
    subprocess.run([str(sdk / 'zipalign'), '-c', '-P', '16', '4', str(apk)], check=True)
    info = subprocess.check_output([str(sdk / 'aapt'), 'dump', 'badging', str(apk)], text=True)
    assert "name='io.github.bug0000.pingtun'" in info and "versionCode='2'" in info
    assert "versionName='" + VERSION + "'" in info and 'application-debuggable' not in info
    assert "sdkVersion:'29'" in info and "native-code: 'arm64-v8a' 'x86_64'" in info
    print('Public APK verified: version, certificate, non-debuggable, ABIs and 16 KiB alignment')


def notices():
    raw = subprocess.check_output(['go', 'list', '-m', '-json', 'all'], cwd=ROOT, text=True)
    decoder, modules = json.JSONDecoder(), []
    while raw.strip():
        item, end = decoder.raw_decode(raw.lstrip())
        modules.append(item)
        raw = raw.lstrip()[end:]
    text = ['Third-party notices for pingtun ' + VERSION, '', 'pingtun: MIT; see LICENSE.', '']
    dependencies = []
    goroot = Path(subprocess.check_output(['go', 'env', 'GOROOT'], text=True).strip())
    text += ['Go standard library', (goroot / 'LICENSE').read_text(), '']
    for module in modules:
        if module.get('Main'):
            continue
        label = module['Path'] + ' ' + module['Version']
        dependencies.append(label)
        directory = Path(module['Dir'])
        found = [directory / name for name in ['LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING', 'NOTICE'] if (directory / name).is_file()]
        if not found:
            raise RuntimeError('Missing license for ' + module['Path'])
        text += [label] + [p.name + '\n' + p.read_text() for p in found] + ['']
    return '\n'.join(text), '\n'.join(dependencies) + '\n'


def package(out):
    out.mkdir(parents=True, exist_ok=True)
    license_text, deps = notices()
    (out / 'THIRD_PARTY_NOTICES.txt').write_text(license_text)
    (out / 'DEPENDENCIES.txt').write_text(deps)
    shutil.copyfile(ROOT / 'RELEASE_NOTES.md', out / 'RELEASE_NOTES.md')
    revision = os.environ.get('SOURCE_SHA') or subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
    for arch in ['amd64', 'arm64']:
        name = 'pingtun_' + VERSION + '_linux_' + arch
        with tempfile.TemporaryDirectory(prefix='pingtun-package-') as temp:
            stage = Path(temp) / name
            (stage / 'bin').mkdir(parents=True)
            env = dict(os.environ, GOOS='linux', GOARCH=arch, CGO_ENABLED='0')
            binary = stage / 'bin/pingtun'
            subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w', '-o', str(binary), './cmd/pingtun'], cwd=ROOT, env=env, check=True)
            if arch == 'amd64':
                assert subprocess.check_output([str(binary), 'version'], text=True).strip() == 'pingtun ' + VERSION
            elif shutil.which('qemu-aarch64'):
                assert subprocess.check_output(['qemu-aarch64', str(binary), 'version'], text=True).strip() == 'pingtun ' + VERSION
                pair = Path(temp) / 'arm64-smoke'
                subprocess.run(['qemu-aarch64', str(binary), 'init', '--server', '192.0.2.1', '--dir', str(pair)], check=True, stdout=subprocess.DEVNULL)
                subprocess.run(['qemu-aarch64', str(binary), 'check', '--config', str(pair / 'server.json')], check=True)
            for document in ['README.md', 'README.ru.md', 'INSTALL.md', 'INSTALL.ru.md', 'LICENSE', 'SECURITY.md', 'PROTOCOL.md', 'LAB.md', 'VALIDATION.md', 'CHANGELOG.md', 'ROADMAP.md', 'VERSION']:
                shutil.copyfile(ROOT / document, stage / document)
            (stage / 'android').mkdir()
            shutil.copyfile(ROOT / 'android/README.md', stage / 'android/README.md')
            shutil.copytree(ROOT / 'deploy', stage / 'deploy')
            (stage / 'THIRD_PARTY_NOTICES.txt').write_text(license_text)
            (stage / 'DEPENDENCIES.txt').write_text(deps)
            info = 'version=' + VERSION + '\nsource=' + revision + '\nGOOS=linux\nGOARCH=' + arch + '\nCGO_ENABLED=0\n'
            info += subprocess.check_output(['go', 'version'], text=True)
            (stage / 'BUILDINFO.txt').write_text(info)
            def normalized(entry):
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = 'root'
                entry.mtime = epoch
                entry.mode = 0o755 if entry.isdir() or entry.name.endswith(('/bin/pingtun', '/deploy/link-up.sh')) else 0o644
                return entry
            with (out / (name + '.tar.gz')).open('wb') as target:
                with gzip.GzipFile(fileobj=target, mode='wb', filename='', mtime=epoch) as compressed:
                    with tarfile.open(fileobj=compressed, mode='w') as archive:
                        archive.add(stage, arcname=name, filter=normalized)
    print('Linux server/client archives and license notices built')


def publish(out):
    if not gate():
        raise RuntimeError('Publication gate is not satisfied')
    m, sha = manifest(), checked_sha()
    apk = download_android(out)
    assert apk.stat().st_size == m['android_size']
    (out / 'ANDROID_SIGNING_CERT.txt').write_text('pingtun ' + VERSION + '\nAPK certificate SHA-256: ' + m['android_certificate_sha256'] + '\n')
    expected = ['pingtun_' + VERSION + '_linux_amd64.tar.gz', 'pingtun_' + VERSION + '_linux_arm64.tar.gz', apk.name,
                'THIRD_PARTY_NOTICES.txt', 'DEPENDENCIES.txt', 'ANDROID_SIGNING_CERT.txt', 'RELEASE_NOTES.md']
    sums = {name: hashlib.sha256((out / name).read_bytes()).hexdigest() for name in expected}
    (out / 'SHA256SUMS').write_text(''.join(sums[name] + '  ' + name + '\n' for name in sorted(sums)))
    sums['SHA256SUMS'] = hashlib.sha256((out / 'SHA256SUMS').read_bytes()).hexdigest()
    releases = api('/repos/' + REPO + '/releases?per_page=100')
    release = next((r for r in releases if r['tag_name'] == 'v' + VERSION), None)
    if release and not release['draft']:
        raise RuntimeError('Release already published; refusing to overwrite assets')
    if release is None:
        release = api('/repos/' + REPO + '/releases', {'tag_name': 'v' + VERSION, 'target_commitish': sha,
            'name': 'pingtun ' + VERSION + ' — Linux + Android / сервер и клиенты',
            'body': (ROOT / 'RELEASE_NOTES.md').read_text(), 'draft': True, 'prerelease': False})
    assets_path = '/repos/' + REPO + '/releases/' + str(release['id']) + '/assets'
    existing = {a['name']: a for a in api(assets_path)}
    for name, digest in sorted(sums.items()):
        if name in existing:
            asset = existing[name]
        else:
            kind = 'application/vnd.android.package-archive' if name.endswith('.apk') else 'application/gzip' if name.endswith('.gz') else 'text/plain; charset=utf-8'
            upload = 'https://uploads.github.com/repos/' + REPO + '/releases/' + str(release['id']) + '/assets?name=' + urllib.parse.quote(name)
            asset = api(upload, (out / name).read_bytes(), content_type=kind)
        assert asset['size'] == (out / name).stat().st_size
        assert asset.get('digest') == 'sha256:' + digest
    assert api('/repos/' + REPO + '/git/ref/heads/main')['object']['sha'] == sha
    result = api('/repos/' + REPO + '/releases/' + str(release['id']), {'draft': False, 'prerelease': False, 'make_latest': 'true'}, method='PATCH')
    print(result['html_url'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['gate', 'download-android', 'verify-apk', 'package', 'publish'])
    parser.add_argument('--out', default=str(ROOT / 'dist'))
    args = parser.parse_args()
    output = Path(args.out).resolve()
    if args.command == 'gate':
        ready = gate()
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as target:
                target.write('ready=' + str(ready).lower() + '\n')
        print('Publication ready: ' + str(ready))
    else:
        {'download-android': download_android, 'verify-apk': verify_apk, 'package': package, 'publish': publish}[args.command](output)
