# -*- coding: utf-8 -*-

# Dependencies:
# * diec (must be installed and added to path manually)
# * clamav
# * libclamunrar9
# * unattended-unipacker (https://github.com/ntnu-rgb/unattended-unipacker)
# * upx

import hashlib
import os
import shutil
import subprocess
import sys

import peutils
import requests

unpack_directory = '/home/sturla/unpacked/'
static_unpack_directory = unpack_directory + 'static/'
generic_unpack_directory = unpack_directory + 'generic/'

tmpdir = '/tmp/unpacking/'

packer_sections = {
    '.aspack': 'aspack',
    'ASPack': 'aspack',
    '.boom': 'boomerang list builder',
    '.ccg': 'ccg packer',
    '.charmve': 'pin tool',
    'BitArts': 'crunch 2.0',
    '.DalKiT': 'dalkrypt',
    '!EPack': 'epack',
    '.ecode': 'built with epl',
    '.edata': 'built with epl',
    '.gentee': 'gentee installer',
    'kkrunchy': 'kkrunchy',
    'lz32.dll': 'crinkler',
    '.mackt': 'imprec',
    '.MaskPE': 'maskpe',
    'MEW': 'mew',
    '.MPRESS1': 'mpress',
    '.MPRESS2': 'mpress',
    '.neolite': 'neolite',
    '.neolit': 'neolite',
    '.nsp1': 'nspack',
    '.nsp0': 'nspack',
    '.nsp2': 'nspack',
    'nsp1': 'nspack',
    'nsp0': 'nspack',
    'nsp2': 'nspack',
    '.packed': 'rlpack packer',
    'pebundle': 'pebundle',
    'PEBundle': 'pebundle',
    'PEC2TO': 'pecompact',
    'PEC2': 'pecompact',
    'pec': 'pecompact',
    'pec1': 'pecompact',
    'pec2': 'pecompact',
    'pec3': 'pecompact',
    'pec4': 'pecompact',
    'pec5': 'pecompact',
    'pec6': 'pecompact',
    'PEC2MO': 'pecompact',
    'PESHiELD': 'Peshield',
    '.petite': 'petite',
    '.pinclie': 'pin tool',
    'ProCrypt': 'procrypt',
    '.RLPack': 'rlpack',
    '.rmnet': 'ramnit virus marker',
    'RCryptor': 'rpcrypt',
    '.RPCrypt': 'rpcrypt',
    '.seau': 'seausfx',
    '.shrink1': 'shrinker',
    '.shrink2': 'shrinker',
    '.shrink3': 'shrinker',
    '.spack': 'simple pack',
    '.svkp': 'svkp',
    '.taz': 'pespin',
    '.tsuarch': 'tsuloader',
    '.tsustub': 'tsuloader',
    'PEPACK!!': 'pepack',
    '.Upack': 'upack',
    '.ByDwing': 'upack',
    'UPX0': 'upx',
    'UPX1': 'upx',
    'UPX2': 'upx',
    'UPX3': 'upx',
    'UPX!': 'upx',
    '.UPX0': 'upx',
    '.UPX1': 'upx',
    '.UPX2': 'upx',
    'VProtect': 'vprotect',
    '.winapi': 'api override tool',
    '_winzip_': 'winzip self-extractor',
    '.WWPACK': 'wwpack',
    '.WWP32': 'wwpack'
}
packer_section_names = set(packer_sections.keys())

protector_sections = {
    '.ASPack': 'asprotect',
    'DAStub': 'dastub dragon armor protector',
    '.enigma1': 'enigma',
    '.enigma2': 'enigma',
    'PELOCKnt': 'pelock',
    '.perplex': 'perplex pe-protector',
    '.sforce3': 'starforce protection',
    '.svkp': 'svk protector',
    'Themida': 'themida',
    '.Themida': 'themida',
    '.vmp0': 'vmprotect',
    '.vmp1': 'vmprotect',
    '.vmp2': 'vmprotect',
    'WinLicen': 'winlicense (themida) protector',
    '.yP': 'y0da protector',
    '.y0da': 'y0da protector'
}
protector_section_names = set(protector_sections.keys())

clam_supported_packers = [
    'aspack',
    'upx',
    'fsg',
    'petite',
    'pespin',
    'nspack',
    'wwpack',
    'mew',
    'upack',
    'y0da protector'
]

unipack_supported_packers = [
    'aspack',
    'fsg',
    'mew',
    'mpress',
    'petite',
    'upx',
    'yzpack'
]

try:
    os.mkdir(tmpdir)       # Create a new temporary directory
except FileExistsError:
    pass

def detect_obfuscation(filepath, pefile_pe, pefile_warnings):
    """
    Attempt to detect obfuscation; Packers, Protectors, etc.
    """
    obfuscation = {'type': 'none'}

    section_names = []
    for section in pefile_pe.sections:
        try:
            section_names.append(section.Name.decode('utf-8').strip('\x00').strip())
        except UnicodeDecodeError:
            continue
    
    protector_intersection = protector_section_names.intersection(section_names)
    if protector_intersection:
        obfuscation = {'type': 'protected', 'protector': protector_sections[protector_intersection.pop()]}
    packer_intersection = packer_section_names.intersection(section_names)
    if packer_intersection:
        obfuscation = {'type': 'packed', 'packer': packer_sections[packer_intersection.pop()]}

    if obfuscation['type'] == 'none':       # Use Detect It Easy to detect packer / protector / linker etc. if it was not detected by section name
        diec_output = get_diec_output(filepath)
        if 'protector' in diec_output:      # If it is protected, overwrite "type".
            obfuscation = {'type': 'protected', 'protector': diec_output['protector']}
        elif 'packer' in diec_output:
            obfuscation = {'type': 'packed', 'packer': diec_output['packer']}
        else:
            # Check if file seems to be packed based on entropy and number of imports 
            # (DIE might not detect all packers)
            # TODO: Investigate peutils -> is_probably_packed(pe) (function)

            # pefile gives warning if the following condition is true:
            # if suspicious_imports_count == len(suspicious_imports) and total_symbols < 20
            # where suspicious_imports are "LoadLibrary" and "GetProcAddress"
            
            much_high_entropy_data = peutils.is_probably_packed(pefile_pe)

            for section_warning in pefile_warnings:
                if ((section_warning == 'Imported symbols contain entries typical of packed executables.')
                        or ('Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are set. This might indicate a packed executable.' in section_warning
                        and much_high_entropy_data)):
                    obfuscation = {'type': 'unknown'}   # Highly likely that it is packed
                    break
    return obfuscation

def get_diec_output(filepath):
    """
    Run Detect It Easy Console on a file specified by a filepath and return values in a dictionary.
    """
    info = {}
    try:
        diec_process = subprocess.run(["diec", filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as err:
        print(err) # TODO: Handle error
    else:
        diec_output = diec_process.stdout.decode('utf-8')
        for line in diec_output.splitlines():
            if line[0:12] == 'PE: packer: ':
                info['packer'] = line[12:].lower()
                for packer in packer_sections.values():
                    if packer in info['packer']:
                        info['packer'] = packer
                        break
            elif line[0:15] == 'PE: protector: ':
                info['protector'] = line[15:].lower()
                for protector in protector_sections.values():
                    if protector in info['protector']:
                        info['protector'] = protector
                        break
            elif line[0:12] == 'PE: linker: ':
                info['linker'] = line[12:]
            elif line[0:14] == 'PE: compiler: ':
                info['compiler'] = line[14:]
            elif line[0:13] == 'PE: library: ':
                info['library'] = line[13:]
            elif line[0:15] == 'PE: installer: ':
                info['installer'] = line[15:]
            elif line[0:13] == 'PE: overlay: ':
                info['overlay'] = line[13:]
            elif line[0:9] == 'PE: sfx: ':
                info['sfx'] = line[9:]
            elif line[0:13] == 'PE: archive: ':
                info['archive'] = line[13:]
            elif line[0:12] == 'PE: joiner: ':
                info['joiner'] = line[12:]
    return info

def unpack_file(filepath, fileinfo, pefile_pe):
    """
    Attempt to unpack a file that has been identified to be packed.
    Returns a list of unpacked files. In most cases an empty list or a list with a single filepath.
    """

    unpacked = []
    if 'protector' in fileinfo['obfuscation'] and fileinfo['obfuscation']['protector'] == 'themida':  # Skip the file if it cannot be unpacked
        return unpacked                                         # (protected by virtualizers and such)

    # is_x86 = pefile_pe.FILE_HEADER.Machine == 0x14c # 0x14c -> Intel 386 or later processors and compatible processors (32-bit PE)
    
    if fileinfo['obfuscation']['type'] == 'packed':
        if 'upx' in fileinfo['obfuscation']['packer']:
            unpacked = unpack_upx(filepath)
        
    if len(unpacked) == 0 and (('packer' in fileinfo['obfuscation'] and fileinfo['obfuscation']['packer'] in clam_supported_packers) or ('protector' in fileinfo['obfuscation'] and fileinfo['obfuscation']['protector'] in clam_supported_packers)):
        unpacked = clam_unpack(filepath)    # Attempt static unpacking with ClamAV

    if len(unpacked) == 0 and 'packer' in fileinfo['obfuscation'] and fileinfo['obfuscation']['packer'] in unipack_supported_packers:
        unpacked = unipack(filepath)        # Attempt to generic unpacking with unipacker

    # Only return files that are not equal to the parent (does not have identical sha256sums):
    return [unpacked_f for unpacked_f in unpacked if  fileinfo['sha256'] != os.path.basename(unpacked_f)]

def unpack_upx(filepath):
    """
    Unpack with UPX

    Dependencies (can be installed from apt repositories in Ubuntu):
    * upx
    """
    tmp_path = os.path.join(tmpdir, os.path.basename(filepath))
    shutil.copyfile(filepath, tmp_path)     # Copy file to unpack directory
    try:
        subprocess.run(["upx", "-d", tmp_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError:
        os.remove(tmp_path)                 # Delete copy if it could not be unpacked
        return []                           # Return an empty list if the file could not be unpacked
    else:
        tmp_path, newfilename = rename_to_sha256(tmp_path)
        newpath = os.path.join(static_unpack_directory, newfilename)
        shutil.move(tmp_path, newpath)      # Move file to directory of unpacked files
        return [newpath]                    # Return new path of the unpacked file if successful

def unipack(filepath):
    """
    Attempt to unpack a file at a given path with unipack.
    Emulates execution over a maximum of 5 seconds in an attempt to unpack PE-files that are packed with "simple" packers.
    Returns a list that can either be empty (could not unpack) or contain a filepath to a file that was unpacked.
    Dependencies:
    * unattended-unipacker [https://github.com/ntnu-rgb/unattended-unipacker]
    """
    try:
        subprocess.run(
            ["unipacker", '-d', generic_unpack_directory, filepath], 
            stdin = subprocess.PIPE, 
            stdout = subprocess.PIPE, 
            stderr = subprocess.PIPE, 
            check=True, 
            timeout=5
        )                       # If it hasn't finished in 5 seconds, it will likely never succeed
    except subprocess.TimeoutExpired:
        return []               # Timeout reached, skip file
    except subprocess.CalledProcessError:
        return []               # unipacker crashed, skip file
    else:
        return [rename_to_sha256(generic_unpack_directory + 'unpacked_' + os.path.basename(filepath))[0]]

def arancino_unpack(filepath):
    """
    url = 'http://henriette.rgb.moe/unpack.php'
    with open(filepath, 'rb') as f:
        r = requests.post(url, files={'upload': f})
        print(r)
        raise SystemExit
        return r.text
    print("Generic unpacking is WIP")
    return None
    """
    return None # TODO: Skipping unpacking since no generic unpacking seems to be successful as of now

def rename_to_sha256(filepath):
    """
    Rename a file specified by a path to the sha256sum of the files and return the new path
    """
    with open(filepath, 'rb') as filehandle:
        rawfile = filehandle.read()
        directory = os.path.dirname(filepath)
        sha256sum = hashlib.sha256(rawfile).hexdigest()
        newpath = directory + '/' + sha256sum
        if filepath != newpath:             # Only rename if it is not already named as the sha256sum
            shutil.move(filepath, newpath)  # Rename file to the sha256sum
        return newpath, sha256sum           # Return the new path of the file and the sha256-sum (filename)
    return None                             # Return None if the file could not be opened

def clam_unpack(filepath):
    """
    Attempt to unpack the malware statically with ClamAV.
    Returns a list that can either be empty or contain paths to files unpacked from the file at the specified path.

    Packers supported by ClamAV [https://www.clamav.net/documents/libclamav]:
    * Aspack (2.12)
    * UPX (all versions)
    * FSG (1.3, 1.31, 1.33, 2.0)
    * Petite (2.x)
    * PeSpin (1.1)
    * NsPack
    * wwpack32 (1.20)
    * MEW
    * Upack
    * Y0da Cryptor (1.3)

    Dependencies (can be installed from apt repositories on Ubuntu):
    * clamav
    * libclamunrar9

    Loading and comparing all signatures typically requires 20 seconds extra runtime.
    To ensure fast execution, remove all signatures and disable signature updates.:
    * Disable the freshclam service: ``service clamav-freshclam stop && systemctl disable clamav-freshclam``
    * Remove all signature files from /var/lib/clamav
    * Add a file "pass.yar" to /var/lib/clamav with the following content:
        rule pass
        {
            condition:
                false
        }
    """
    unpacked = []

    try:
        subprocess.run([
                'clamscan', 
                '--debug', 
                '--leave-temps=yes', 
                '--tempdir='+tmpdir, 
                '--no-summary',
                '--bytecode=no',
                '--scan-mail=no',
                '--phishing-sigs=no',
                '--phishing-scan-urls=no',
                '--heuristic-alerts=no',
                '--scan-pe=yes', 
                '--scan-elf=no',
                '--scan-ole2=no',
                '--scan-pdf=no',
                '--scan-swf=no',
                '--scan-html=no',
                '--scan-xmldocs=no',
                '--scan-hwp3=no',
                filepath
            ], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            check=True,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        print('Timeout reached for ClamAV')
        return unpacked             # Timeout reached, return empty list
    except subprocess.CalledProcessError:
        return unpacked             # clamscan crashed, return empty list
    else:
        for root, dirs, files in os.walk(tmpdir, topdown=False):
            for filename in files:
                oldpath, newfilename = rename_to_sha256(os.path.join(root, filename))
                newpath = os.path.join(static_unpack_directory, newfilename)
                shutil.move(oldpath, newpath)
                unpacked.append(newpath)
            for dirname in dirs:
                os.rmdir(os.path.join(root, dirname))
        return unpacked
