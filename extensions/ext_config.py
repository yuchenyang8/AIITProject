from web.utils.auxiliary import get_yaml

CONFIG_PATH = 'extensions\\ext_config.yaml'
DOCS = get_yaml(CONFIG_PATH)

# Whatweb
WHATWEB_DIR = DOCS['whatweb']['dir']

# Dirsearch
DIRSEARCH_DIR = DOCS['dirsearch']['dir']
DIRSEARCH_RESULT_DIR = DOCS['dirsearch']['result_dir']

# Wafw00f
WAFW00F_DIR = DOCS['wafw00f']['dir']
WAFW00F_RESULT_DIR = DOCS['wafw00f']['result_dir']

# Hydra
HYDRA_DIR = DOCS['hydra']['dir']
HYDRA_THREAD = DOCS['hydra']['thread']
HYDRA_DICT_USERNAME = DOCS['hydra']['username']
HYDRA_DICT_PASSWORD = DOCS['hydra']['password']

# Xray
XRAY_DIR = DOCS['xray']['dir']
RAD_DIR = DOCS['xray']['rad_dir']
CHROME_DIR = DOCS['xray']['chrome_dir']

# Nessus
NESSUS_URL = DOCS['nessus']['url']
NESSUS_ACCESSKEY = DOCS['nessus']['accesskey']
NESSUS_SECRETKEY = DOCS['nessus']['secretkey']

# Pocsuite
POC_DIR = DOCS['pocsuite']['dir']

# MobSF
MOBSF_URL = DOCS['mobsf']['url']
MOBSF_APIKEY = DOCS['mobsf']['apikey']
APP_FOLDER = DOCS['mobsf']['folder']

# Binwalk
FIRMWARE_FOLDER = DOCS['binwalk']['folder']

# Others
SUPPORT_PROTOCOL = ['ssh', 'ftp', 'mysql']
