# -*- coding: utf-8 -*-

# Dependencies:
# diec (manual install)

import subprocess

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
    '.packed': 'unknown packer',
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
            if 'Imported symbols contain entries typical of packed executables.' in pefile_warnings:
                obfuscation = {'type': 'unknown'}
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