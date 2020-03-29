# -*- coding: utf-8 -*-

# External dependencies:
# * pefile
# * requests
# * diec - https://github.com/horsicq/Detect-It-Easy (must be installed and added to path manually)
# * clamav
# * libclamunrar9
# * upx

import configparser
import hashlib
import os
import shutil
import subprocess
import sys
import time
import tempfile

import peutils
import requests

config = configparser.ConfigParser()
config.read('config.ini')
unpack_directory = config.get('clustering', 'unpacking_base_directory')

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

# Create necessary directory if it does not exist
if not os.path.exists(unpack_directory):
    os.makedirs(unpack_directory)

def detect_obfuscation(filepath, pefile_pe, pefile_warnings):
    """
    Attempt to detect obfuscation; Packers, Protectors, etc.
    Attempts to detect obfuscation through various methods;
    Identifying section names used by common packers, DetectItEasy,
    or by identifying if file seems to contain few imports and high entropy data.
    """
    obfuscation = {'type': 'none'}

    # Attempt to detect packing by section names
    obfuscation = detect_obfuscation_by_section_names(pefile_pe)

    if obfuscation['type'] == 'none':
        # Use Detect It Easy to detect packer/protector etc. if it was not detected by section name
        obfuscation = detect_obfuscation_by_diec(filepath)
    if obfuscation['type'] == 'none':
        # Check if file seems to be packed based on entropy and imports
        obfuscation = detect_obfuscation_by_section_properties(pefile_pe, pefile_warnings)
    return obfuscation

def detect_obfuscation_by_section_names(pefile_pe):
    """
    Detect obfuscation by checking for section names that are
    known to belong to packers or protectors.
    """
    section_names = []
    for section in pefile_pe.sections:
        try:
            section_names.append(section.Name.decode('utf-8').strip('\x00').strip())
        except UnicodeDecodeError:
            continue
    
    protector_intersection = protector_section_names.intersection(section_names)
    if protector_intersection:
        return {'type': 'protected', 'protector': protector_sections[protector_intersection.pop()]}
    packer_intersection = packer_section_names.intersection(section_names)
    if packer_intersection:
        return {'type': 'packed', 'packer': packer_sections[packer_intersection.pop()]}
    return {'type': 'none'}

def detect_obfuscation_by_diec(filepath):
    """
    Detect obfuscaton with DetectItEasy
    """
    diec_output = get_diec_output(filepath)
    if 'protector' in diec_output:      # If it is protected, overwrite "type".
        return {'type': 'protected', 'protector': diec_output['protector']}
    elif 'packer' in diec_output:
        return {'type': 'packed', 'packer': diec_output['packer']}
    return {'type': 'none'}

def get_diec_output(filepath):
    """
    Run Detect It Easy Console on a file specified by a filepath and return values in a dictionary.
    """
    info = {}
    try:
        diec_process = subprocess.run(["diec", filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as err:
        print(err) # TODO: Handle error
    except OSError as err:
        print(err)
        print("Sleeping 5 minutes before trying again")
        time.sleep(300)
        return get_diec_output(filepath)
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

def detect_obfuscation_by_section_properties(pefile_pe, pe_warnings):
    """
    Detect obfuscation through properties of sections.

    # pefile gives warning if the following condition is true:
    # if suspicious_imports_count == len(suspicious_imports) and total_symbols < 20
    # where suspicious_imports are "LoadLibrary" and "GetProcAddress"
    """
    much_high_entropy_data = peutils.is_probably_packed(pefile_pe)
    for section_warning in pe_warnings:
        if ((section_warning == 'Imported symbols contain entries typical of packed executables.')
                or ('Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are set. This might indicate a packed executable.' in section_warning
                and much_high_entropy_data)):   # Likely that it is packed if high entropy
            return {'type': 'unknown'}          # data and a section is both writable and
    return {'type': 'none'}                     # executable or only few specific imports.

def unpack_file(filepath, fileinfo, pefile_pe):
    """
    Attempt to unpack a file that has been identified to be packed.
    Returns a list of unpacked files. In most cases an empty list or a list with a single filepath.
    """

    tmpfile_object = tempfile.TemporaryDirectory()
    tmpdir = tmpfile_object.name

    unpacked = []
    if 'protector' in fileinfo['obfuscation'] and fileinfo['obfuscation']['protector'] == 'themida':  # Skip the file if it cannot be unpacked
        return unpacked                                         # (protected by virtualizers and such)

    # is_x86 = pefile_pe.FILE_HEADER.Machine == 0x14c # 0x14c -> Intel 386 or later processors and compatible processors (32-bit PE)
    
    if fileinfo['obfuscation']['type'] == 'packed':
        if 'upx' in fileinfo['obfuscation']['packer']:
            unpacked = unpack_upx(filepath, tmpdir)
        
    if not unpacked and (('packer' in fileinfo['obfuscation'] and fileinfo['obfuscation']['packer'] in clam_supported_packers) or ('protector' in fileinfo['obfuscation'] and fileinfo['obfuscation']['protector'] in clam_supported_packers)):
        # Attempt static unpacking with ClamAV
        unpacked = clam_unpack(filepath, tmpdir)

    # Only return files that are not equal to the parent (does not have identical sha256sums):
    return [unpacked_f for unpacked_f in unpacked if  fileinfo['sha256'] != os.path.basename(unpacked_f)]

def unpack_upx(filepath, tmpdir):
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
    except OSError as err:
        print(err)
        print("Sleeping 5 minutes before trying again")
        time.sleep(300)
        return unpack_upx(filepath, tmpdir)
    else:
        tmp_path, newfilename = rename_to_sha256(tmp_path)
        newpath = os.path.join(unpack_directory, newfilename)
        shutil.move(tmp_path, newpath)      # Move file to directory of unpacked files
        return [newpath]                    # Return new path of the unpacked file if successful

def clam_unpack(filepath, tmpdir):
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
        return unpacked             # Timeout reached, return empty list
    except subprocess.CalledProcessError:
        return unpacked             # clamscan crashed, return empty list
    except OSError as err:
        print(err)
        print("Sleeping 5 minutes before trying again")
        time.sleep(300)
        return clam_unpack(filepath, tmpdir)
    else:
        for root, dirs, files in os.walk(tmpdir, topdown=False):
            for filename in files:
                oldpath, newfilename = rename_to_sha256(os.path.join(root, filename))
                newpath = os.path.join(unpack_directory, newfilename)
                shutil.move(oldpath, newpath)
                unpacked.append(newpath)
            for dirname in dirs:
                os.rmdir(os.path.join(root, dirname))
        return unpacked

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
        return newpath, sha256sum       # Return the new path of the file and the sha256-sum (filename)
    return None, None                       # Return None if the file could not be opened
