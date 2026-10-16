# Read-only publication receipt collection. Capture stable-before.json before dispatch.
from pathlib import Path
import json,subprocess,sys
root,tag,expected=sys.argv[1:]
root=Path(root)
root.mkdir(exist_ok=True)
if not (root/'stable-before.json').exists():
    raise SystemExit('Capture stable-before.json before publication first.')
repo='ysya/sshelter'
def api(endpoint,name):
    data=subprocess.check_output(['gh','api',f'repos/{repo}/{endpoint}'],text=True)
    (root/name).write_text(data)
    return json.loads(data)
api(f'releases/tags/{tag}','release.json')
api('releases/latest','stable.json')
api('releases/tags/updater-beta','channel-release.json')
ref=api(f'git/ref/tags/{tag}','tag.json')
if ref['object']['type']=='tag':
    api('git/tags/'+ref['object']['sha'],'annotated-tag.json')
for name,folder in [(tag,'release'),('updater-beta','channel')]:
    dest=root/folder
    dest.mkdir(exist_ok=True)
    subprocess.run(['gh','release','download',name,'--repo',repo,'--pattern','latest.json','--dir',str(dest),'--clobber'],check=True)
sigdir=root/'signatures'
sigdir.mkdir(exist_ok=True)
subprocess.run(['gh','release','download',tag,'--repo',repo,'--pattern','*.sig','--dir',str(sigdir),'--clobber'],check=True)
result=subprocess.check_output(['node',str(Path(__file__).with_name('verify-publication.mjs')),str(root),tag,expected],text=True)
(root/'verification.log').write_text(result)
print(result)
