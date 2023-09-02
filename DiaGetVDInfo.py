#!/usr/bin/env python
# coding: utf-8


import sys
import comtypes
import comtypes.client

# this has to be before the import that follows
# msdia = comtypes.client.GetModule(r'C:\Program Files (x86)\Common Files\Microsoft Shared\VC\amd64\msdia80.dll')
msdia = comtypes.client.GetModule(r'msdia80.dll')

from comtypes.gen.Dia2Lib import *

try:
    dia = comtypes.client.CreateObject(msdia.DiaSource)
except Exception as exc:
    print("Exception creating DIA object: %s\nAs admin run regsvr32.exe msdia80.dll" % (str(exc)))
    sys.exit(1)




import pefile
import os
import requests
import shutil    

SYMBOLS_SERVER = 'https://msdl.microsoft.com/download/symbols'

class PEFile(pefile.PE):
    def __init__(self, path):
        pefile.PE.__init__(self, path)
        
        self.path = path
        self.pdbFileName = None
        self.pdbObj = None
        self.symbols = None

    def downloadPDB(self, localCache=r'Z:\Symbols'):
        def getPDBURL(pe):
            #pe.parse_data_directories()
            string_version_info = {}
            for fileinfo in pe.FileInfo[0]:
                if fileinfo.Key.decode() == 'StringFileInfo':
                        for st in fileinfo.StringTable:
                                for entry in st.entries.items():
                                    string_version_info[entry[0].decode()] = entry[1].decode()
            verStr = string_version_info['ProductVersion']
            for directory in pe.DIRECTORY_ENTRY_DEBUG:
                debug_entry = directory.entry
                if hasattr(debug_entry, 'PdbFileName'):
                    pdb_file = debug_entry.PdbFileName[:-1].decode('ascii')
                    guid = f'{debug_entry.Signature_Data1:08x}'
                    guid += f'{debug_entry.Signature_Data2:04x}'
                    guid += f'{debug_entry.Signature_Data3:04x}'
                    guid += f'{int.from_bytes(debug_entry.Signature_Data4, byteorder="big"):016x}'
                    guid = guid.upper()
                    url = f'/{pdb_file}/{guid}{debug_entry.Age:x}/{pdb_file}'
                    pdbFileName = f'{pdb_file[:-4]}-{verStr}.pdb'
                    return url, pdbFileName
            return None

        path = self.path
        pdbUrl, pdbFileName = getPDBURL(self)
        if not os.path.exists(pdbFileName):
            pdbPath = pdbFileName
            if os.path.exists(localCache):
                pdbPath = localCache + pdbUrl
                pdbPath = os.path.realpath(pdbPath)
            if not os.path.exists(pdbPath):
                r = requests.get(SYMBOLS_SERVER + pdbUrl)
                r.raise_for_status()
                with open(pdbPath, 'wb') as f:
                    f.write(r.content)
            if pdbPath != pdbFileName:
                shutil.copyfile(pdbPath, pdbFileName)
        self.pdbFileName = pdbFileName
    
    def loadPDB(self):
        self.downloadPDB()
        try:
            dia = comtypes.client.CreateObject(msdia.DiaSource)
            dia.loadDataFromPdb(self.pdbFileName)
            diaSession = dia.openSession()
        except Exception as exc:
            print(('[!] loadDataFromPdb() error %s' % (str(exc))))
            raise
        self.pdbObj = diaSession

twinuipcshell = PEFile(r"C:\Windows\System32\twinui.pcshell.dll")
twinuipcshell.loadPDB()
actxprxy = PEFile(r"C:\Windows\System32\actxprxy.dll")
actxprxy.loadPDB()




udtEnumToStr = ('struct', 'class', 'union', 'interface')
# Utility class for capturing some of the data from UDT symbol list in PDB file
class PDBSymbol:

    @classmethod
    def fromDia(cls, symbol_data):
        return PDBSymbol(udtEnumToStr[symbol_data.udtKind], symbol_data.name, symbol_data.undecoratedName, symbol_data.virtualAddress, symbol_data.length)
    
    def __init__(self, kind = '', name = '', undName = '', rva = 0, size = 0):

        self.kind = kind
        self.name = name
        self.undName = undName
        self.rva = rva
        self.size = size
        self.pe = None

    def __str__(self):

        sstr = '0x%08x (%4dB) %s\t%s' % (self.rva, self.size, self.kind, self.name)

        return sstr

    def __repr__(self):
        return f'<PDBSymbol {str(self)}>'

    # required for hash
    def __hash__(self):
        return hash((self.name, self.rva, self.kind))

    # required for hash, when buckets contain multiple items
    def __eq__(self, other):
        return (self.name == other.name and self.rva == other.rva and self.kind == other.kind)
    
    def __contains__(self, key):
        return self.__eq__(key)
    
    def readData(self, length=None):
        if length is None:
            length = self.size
        
        return self.pe.get_data(self.rva, length)

# EOF




# symb = twinuipcshell.pdbObj.globalScope.findChildren(SymTagPublicSymbol, None, 0)[100]
# symbol_data = symb.QueryInterface(IDiaSymbol)
# print(symbol_data.name, symbol_data.virtualAddress, )
# hex(twinuipcshell.get_dword_at_rva(symbol_data.virtualAddress))




# parse the input PDB
def parsePDB(pe):
    pdbObj = pe.pdbObj
    syms = set()

    # iterate the public syms to find all vtables
    for symb in pdbObj.globalScope.findChildren(SymTagPublicSymbol, None, 0):
        symbol_data = symb.QueryInterface(IDiaSymbol)
        symbol_obj = PDBSymbol.fromDia(symbol_data)
    
        syms.add(symbol_obj)

        #print(symbol_data.undecoratedName, symbol_data.name)

    # iterate all UDT/private? symbols
    for symb in pdbObj.globalScope.findChildren(SymTagUDT, None, 0):
        symbol_data = symb.QueryInterface(IDiaSymbol)
        #print(symbol_data.undecoratedName, symbol_data.name)
        symbol_obj = PDBSymbol.fromDia(symbol_data)
    
        syms.add(symbol_obj)
    

    syms = list(syms)
    for sym in syms:
        sym.pe = pe
    return syms

twinuipcshell.symbols = parsePDB(twinuipcshell)
actxprxy.symbols = parsePDB(actxprxy)




symMap = {c.name: c for c in twinuipcshell.symbols + actxprxy.symbols}



# dump guid
def GUIDToStr(guidbytes):
    return '%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X' % (
        int.from_bytes(guidbytes[:4], 'little'),
        int.from_bytes(guidbytes[4:6], 'little'),
        int.from_bytes(guidbytes[6:8], 'little'),
        *[int.from_bytes(guidbytes[i:i+1], 'little') for i in range(8, 16)]
    )

def printGuidSym(symName):
    print("%s: %s" % (symName, GUIDToStr(symMap[symName].readData())))

# printGuidSym("IID_IVirtualDesktopManagerInternal")
# printGuidSym("IID_IVirtualDesktop")
# printGuidSym("IID_IVirtualDesktopManager")
# printGuidSym("IID_IVirtualDesktopPinnedApps")

iid_ordered = []

for (k, _) in symMap.items():
    if "IID_IVirtualDesktop" in k:
        iid_ordered.append(k)

iid_ordered.sort()
for k in iid_ordered:
    printGuidSym(k)

def cleanMethodName(methodDef):
    if "RuntimeClassImpl" in methodDef:
        methodName = methodDef.split('Microsoft::WRL::Details::RuntimeClassImpl<')[1].split('>::')[1]
        return methodName
    else:
        return methodDef

# dump vft
def dumpVFT(vftName):
    vftSym = symMap[vftName]
    clsName = vftSym.undName # vftSym.undName.split('::')[0]
    print("\n\nDumping vftable: %s" % clsName)
    vftData = vftSym.readData()
    vftPtrs = [int.from_bytes(vftData[c:c+8], 'little') - vftSym.pe.OPTIONAL_HEADER.ImageBase for c in range(0, len(vftData), 8)]
    symMap2 = {c.rva: c for c in vftSym.pe.symbols}
    for i, ptr in enumerate(vftPtrs):
        if ptr in symMap2:
            if "::Release" in symMap2[ptr].undName:
                print("    Method %2d: Release" % i)
            elif "::AddRef" in symMap2[ptr].undName:
                print("    Method %2d: AddRef" % i)
            elif "::QueryInterface" in symMap2[ptr].undName:
                print("    Method %2d: QueryInterface" % i)
            elif "deleting destructor'" in symMap2[ptr].undName:
                print("    Method %2d: ~Destructor" % i)
            else:
                # print("    Method %2d: %s (%s)" % (i, symMap2[ptr].undName, symMap2[ptr].name))
                # print("    Method %2d: %s" % (i, symMap2[ptr].undName))
                print("    Method %2d: %s" % (i, cleanMethodName(symMap2[ptr].undName)))
        else:
            print("    Method %2d: Unknown (0x%X)" % (i, ptr))

#symMap['??_7CVirtualDesktopManager@@6BIVirtualDesktopManagerInternal@@@'].pe

vft_allowed = ["CVirtualDesktop", "VirtualDesktopsApi", "CVirtualDesktopManager", "CVirtualDesktopNotificationsDerived", "CVirtualDesktopNotifications", "CVirtualDesktopVisibilityPolicy"]
vft_ordered = []

for (k, _) in symMap.items():
    for vft_allowed_name in vft_allowed:
        if ("_7%s@" % vft_allowed_name) in k:
            vft_ordered.append(k)
            break
    # if "??_7CVirtualDesktop" in k:
    #     if "CVirtualDesktopBarElement" in k:
    #         continue
    #     print(k)
    #     vft_ordered.append(k)
# vft_ordered.append('??_7VirtualDesktopsApi@@6B@')
vft_ordered.sort()


for k in vft_ordered:
    dumpVFT(k)


"""
??_7CVirtualDesktopManager@@6BIImmersiveWindowMessageNotification@@@
??_7CVirtualDesktopHotkeyHandler@@6B?$ChainInterfaces@UIVirtualDesktopHotkeyHandlerPrivate@@UIVirtualDesktopHotkeyHandler@@VNil@Details@WRL@Microsoft@@V3456@V3456@V3456@V3456@V3456@V3456@V3456@@WRL@Microsoft@@@
??_7CVirtualDesktopComponent@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00UIServiceProvider@@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopManager@@6BIWeakReferenceSource@@@
??_7CVirtualDesktopHolographicViewTransitionNotification@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00U?$ImplementsMarker@VFtmBase@WRL@Microsoft@@@Details@23@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopManager@@6BIInspectable@@@
??_7CVirtualDesktopHotkeyHandler@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00U?$ChainInterfaces@UIVirtualDesktopHotkeyHandlerPrivate2@@UIVirtualDesktopHotkeyHandlerPrivate@@VNil@Details@WRL@Microsoft@@V3456@V3456@V3456@V3456@V3456@V3456@V3456@@23@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopCollection@@6B@
??_7CVirtualDesktopHolographicViewTransitionNotification@@6BIHolographicViewTransitionNotification@@@
??_7CVirtualDesktop@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$02@WRL@Microsoft@@$00U?$ImplementsMarker@VFtmBase@WRL@Microsoft@@@Details@23@@Details@WRL@Microsoft@@@
??_7CVirtualDesktop@@6BIVirtualDesktopPrivate@@@
??_7CVirtualDesktopNotificationsDerived@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00U?$ImplementsMarker@VFtmBase@WRL@Microsoft@@@Details@23@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopContainerElement@@6B?$Selector@U?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00UIObservableObjectArrayChanged@@UIVirtualDesktopContainerElement@@UIScrollableElement@@@Details@WRL@Microsoft@@U?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$0A@U?$ImplementsMarker@VCMultitaskingViewElementBase@@@Details@23@UIObservableObjectArrayChanged@@UIVirtualDesktopContainerElement@@UIScrollableElement@@@234@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopContainerElement@@6B?$Selector@VCMultitaskingViewElementBase@@U?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$0A@U?$ImplementsMarker@VCMultitaskingViewElementBase@@@Details@23@UIObservableObjectArrayChanged@@UIVirtualDesktopContainerElement@@UIScrollableElement@@@Details@WRL@Microsoft@@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopSwitcherService@@6BIVirtualDesktopSwitcherService@@@
??_7CVirtualDesktopApplicationViewEventListener@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00U?$ImplementsMarker@VFtmBase@WRL@Microsoft@@@Details@23@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopSwitcherService@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00UIVirtualDesktopSwitcherInvoker@@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopVisibilityPolicy@@6B@
??_7CVirtualDesktopContainerElement@@6BIVirtualDesktopContainerElement@@@
??_7CVirtualDesktopLock@@6B@
??_7CVirtualDesktop@@6B?$ChainInterfaces@UIVirtualDesktop2@@UIVirtualDesktop@@VNil@Details@WRL@Microsoft@@V3456@V3456@V3456@V3456@V3456@V3456@V3456@@WRL@Microsoft@@@
??_7CVirtualDesktopSoftLandingHandler@@6BIVirtualDesktopSoftLandingHandler@@@
??_7CVirtualDesktopDefaultForegroundHandler@@6B@
??_7CVirtualDesktopApplicationViewEventListener@@6BIApplicationViewChangeListener@@@
??_7CVirtualDesktopSoftLandingHandler@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00UIApplicationViewChangeListener@@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopSoftLandingHandler@@6B@
??_7CVirtualDesktopComponent@@6B?$Selector@U?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00U?$ImplementsMarker@VFtmBase@WRL@Microsoft@@@Details@23@@Details@WRL@Microsoft@@U?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$0A@U?$ImplementsMarker@VCImmersiveShellComponentWithGITSite@@@Details@23@VFtmBase@23@@234@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopManager@@6BIVirtualDesktopManagerInternal2@@@
??_7CVirtualDesktopFactory@@6B@
??_7CVirtualDesktopComponent@@6B?$Selector@VCImmersiveShellComponentWithGITSite@@U?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$0A@U?$ImplementsMarker@VCImmersiveShellComponentWithGITSite@@@Details@23@VFtmBase@23@@Details@WRL@Microsoft@@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopManager@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$02@WRL@Microsoft@@$00UISuspendableVirtualDesktopManager@@UIImmersiveWindowMessageNotification@@VFtmBase@23@@Details@WRL@Microsoft@@@
??_7CVirtualDesktop@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$02@WRL@Microsoft@@$00UIWeakReferenceSource@@UIVirtualDesktopPrivate@@VFtmBase@23@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopNotificationsDerived@@6B@
??_7CVirtualDesktopManager@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$02@WRL@Microsoft@@$00UIVirtualDesktopManagerInternal@@UIVirtualDesktopManagerInternal2@@UISuspendableVirtualDesktopManager@@UIImmersiveWindowMessageNotification@@VFtmBase@23@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopNotificationsDerived@@6BIVirtualDesktopNotification@@@
??_7CVirtualDesktopComponent@@6BIImmersiveShellComponent@@@
??_7CVirtualDesktopContainerElement@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$01@WRL@Microsoft@@$00UIScrollableElement@@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopSwitcherService@@6B@
??_7CVirtualDesktop@@6B@
??_7CVirtualDesktopManager@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$02@WRL@Microsoft@@$00U?$ImplementsMarker@VFtmBase@WRL@Microsoft@@@Details@23@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopManager@@6B?$ImplementsHelper@U?$RuntimeClassFlags@$02@WRL@Microsoft@@$00U?$ChainInterfaces@UIVirtualDesktopManagerPrivate@@UIVirtualDesktopManagerInternal@@UIVirtualDesktopManagerInternal2@@VNil@Details@WRL@Microsoft@@V4567@V4567@V4567@V4567@V4567@V4567@@23@UIWeakReferenceSource@@UIVirtualDesktopManagerInternal@@UIVirtualDesktopManagerInternal2@@UISuspendableVirtualDesktopManager@@UIImmersiveWindowMessageNotification@@VFtmBase@23@@Details@WRL@Microsoft@@@
??_7CVirtualDesktopForegroundPolicy@@6B@

"""


