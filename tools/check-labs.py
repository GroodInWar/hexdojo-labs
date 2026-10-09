import ast
import subprocess
from pathlib import Path
for file in Path('network-0').glob('*.py'): ast.parse(file.read_text(),filename=str(file))
for file in Path('network-0').glob('*.sh'): subprocess.run(['sh','-n',str(file)],check=True)
text=Path('network-0/compose.yaml').read_text()
for denied in ['privileged:', 'network_mode:', 'pid:', 'ipc:', 'ports:', 'volumes:', 'docker.sock']: assert denied not in text,denied
for required in ['internal: true', 'read_only: true', 'cap_drop: [ALL]', 'no-new-privileges:true', 'pids_limit:', 'mem_limit:', 'cpus:']: assert required in text,required
assert not Path('network-0/challenge.py').exists()
print('PASS guided lab syntax and configuration boundaries; live VM isolation is not tested')
