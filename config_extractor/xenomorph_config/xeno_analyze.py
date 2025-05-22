import magic
import re
import os
import subprocess
import traceback

from xenomorph_config.xeno_decrypt import XenoDecrypt

# ### EXTERNAL FUNCTIONS #############################################################################################

class XenoAnalyze:
    # grep
    def grep(self, OPTIONS, STRING_, DIR, CASE):
        TOOL = 'grep'

        # regular grep e.g., DexClassLoader / attachBaseContext / dexName
        if CASE == 0:
            try:
                print("  [-] Attempting to grep '{0}' from files...".format(STRING_))
                p = subprocess.Popen([TOOL, OPTIONS, STRING_, DIR], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = p.communicate()
                if output.strip():
                    pass
                else:
                    print("  Item was not found")
            except Exception as e:
                print("    [-] Error during grep '{0}'...".format(STRING_))
                print(type(e).__name__, ":", e)
                print(traceback.format_exc())
            print("    [-] Successful grep '{0}'".format(STRING_))
            return(output.decode())

        # grep arr to be decrypted 
        elif CASE == 1:
            arr_forLoop = []
            classNames = self.getClassNames(DIR)
            
            try:
                print("  [-] Attempting to grep array to be decrypted from files...")
                p = subprocess.Popen([TOOL, OPTIONS, STRING_, DIR], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = p.communicate()
                if output.strip():
                    print("    [-] Successful grep array to be decrypted")
                    for line in output.decode().split('\n'):
                        arr = line.split(':')[0].strip()
                        if arr and arr not in arr_forLoop and arr not in classNames:
                            arr_forLoop.append(arr)
                else:
                    print("  Item was not found")
            except Exception as e:
                print("    [-] Error during grep array to be decrypted...")
                print(type(e).__name__, ":", e)
                print(traceback.format_exc())

            return arr_forLoop

        # grep tuple for decryption
        elif CASE == 2:
            tuple_forLoop = []
            try:
                print("  [-] Attempting to grep tuple for decryption...")
                p = subprocess.Popen([TOOL, OPTIONS, STRING_, DIR], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = p.communicate()
                if output.strip():
                    print("    [-] Successful grep tuple for decryption")
                    for line in output.decode().split('\n'):
                        if line:
                            tuple_forLoop.append(line.split('(')[1].split(')')[0])
                else:
                    print("  Item was not found")
            except Exception as e:
                print("    [-] Error during grep tuple for decryption...")
                print(type(e).__name__, ":", e)
                print(traceback.format_exc())

            return tuple_forLoop
            
    # dexdump
    def getClassNames(self, dexFilePath):
        classNames = []

        TOOL = 'dexdump'
        try:
            p = subprocess.Popen([TOOL, dexFilePath], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = p.communicate()
            for item in output.decode().split('\n'):
                if "Class descriptor" in item:
                    className = item.strip().split(": 'L")[1].split("'")[0]
                    classNames.append(className)
        except Exception as e:
            print("    [-] Error during retrieve class names... File may not be a dex file")
            print(type(e).__name__, ":", e)
            print(traceback.format_exc())

        return classNames

    # ### ANALYZE ########################################################################################################

    def setFileDetails_dropped(self, payloadDir_path, payloadFile_path):
        # Get class names from classes.dex (dexdump)
        file_details = {}
        decryptedFiles = []

        if re.search("dex", magic.from_file(payloadFile_path), re.IGNORECASE):
            decryptedFiles.append(payloadFile_path)

        decrypted_file = payloadFile_path

        # Get class names (dexdump)
        deobf_allClasses = {}
        matched_strings = []
        domainNames = []
        classNames = self.getClassNames(payloadFile_path)
        for className in classNames:
            deobf_list = []

            # Get deobfuscated strings for each class
            if "ApiGetCommandsResponsePayload;" in className:
                className = className.replace(";", "")
                xenoCommands = ["sms_log", "notif_ic_disable", "inj_list", "notif_ic_enable", "sms_ic_disable", "inj_enable", 
                                "app_list", "sms_ic_enable", "inj_update", "inj_disable", "sms_ic_update", "sms_ic_list", 
                                "notif_ic_list", "self_cleanup", "notif_ic_update", "fg_disable", "fg_enable", "app_kill"]
                classFile_path = os.path.join(payloadDir_path, 'sources', className.replace('.', '/')+'.java')
                print("  [-] Analysing", classFile_path)

                # Get deobfuscated strings
                grep_arr = self.grep('-rEzo', r"\{('?([[:print:]]){1-2}'?|-?[[:digit:]]+)((,[[:space:]]*)?('?([[:print:]]){1-2}'?|-?[[:digit:]]+))*\}", classFile_path, 1)
                if grep_arr:
                    for arr in grep_arr:
                        arr = [int(item) for item in arr.split('{')[1].split('}')[0].split(', ')]
                grep_tuple = self.grep('-rEo', r"\((-?[[:digit:]]+),[[:space:]]*(-?[[:digit:]]+),[[:space:]]*(-?[[:digit:]]+)\)", classFile_path, 2)
                if grep_tuple:
                    for tup in grep_tuple:
                        tup = [int(item) for item in tup.split(', ')]
                        i = tup[0]
                        i2 = tup[1]
                        i3 = tup[2]
                        deobf_list.append(XenoDecrypt.decrypt(i, i2, i3, arr))
                
                # Check % match with list of xenoCommands
                with open(classFile_path, 'r', encoding='iso-8859-1') as file:
                    match = []
                    # If file originally contains obfuscated strings, check for match of xenoCommands against the deobfuscated strings
                    if deobf_list:
                        for string in xenoCommands:
                            if string in deobf_list:
                                match.append(True)
                                matched_strings.append(string)
                            else:
                                match.append(False)
                        deobf_allClasses[className] = deobf_list
                    # Else, check for match of xenoCommands against the file itself
                    else:
                        fileStrings = file.read()
                        for string in xenoCommands:
                            if string in fileStrings:
                                match.append(True)
                                matched_strings.append(string)
                            else:
                                match.append(False)
                        file.close()
                percentMatch = sum(match) / len(match)
                if percentMatch >= 0.75:
                    file_details["family"] = "xenomorph"
            if "Constants;" in className:
                className = className.replace(";", "")
                constantsStrings = ["metrics", "ping", "5f9e4a92b1d8c8b98db9b7f8f8800d2e", 
                                    "com.android.packageinstaller:id/permission_allow_button" , "com.android.permissioncontroller:id/permission_allow_button", "com.android.settings:id/action_button", "com.android.settings:id/button1", "android:id/button1",
                                    "4e7d36521f246327efffde4e5f3d1705bacff85a7d3cf1836d31714196434d79", "f82847a89d3e776505ab6af6cf2d0298455b52f9e9741cd0d9d3714451a96aff", "d83fa5b262824b544ed5565164a1791e29d015bdd325461ed9344a9a5b60c9b5", "34a6a777402003a51fa70f4184ec8340c4dda695849309bbf5647648b2c3c62d",
                                    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.WAKE_LOCK", "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.ACCESS_NETWORK_STATE", "android.permission.INTERNET", "android.permission.READ_PHONE_STATE", "android.permission.USE_FULL_SCREEN_INTENT", "android.permission.FOREGROUND_SERVICE", "android.permission.READ_PHONE_NUMBERS"
                                    ]
                classFile_path = os.path.join(payloadDir_path, 'sources', className.replace('.', '/')+'.java')
                print("  [-] Analysing", classFile_path)

                # Get deobfuscated strings
                grep_arr = self.grep('-rEzo', r"\{('?([[:print:]]){1-2}'?|-?[[:digit:]]+)((,[[:space:]]*)?('?([[:print:]]){1-2}'?|-?[[:digit:]]+))*\}", classFile_path, 1)
                if grep_arr:
                    if len(grep_arr) > 1:
                        grep_arr = [' '.join(grep_arr)]
                    for arr in grep_arr:
                        arr = [int(item) for item in arr.split('{')[1].split('}')[0].split(', ')]
                grep_tuple = self.grep('-rEo', r"\((-?[[:digit:]]+),[[:space:]]*(-?[[:digit:]]+),[[:space:]]*(-?[[:digit:]]+)\)", classFile_path, 2)
                if grep_tuple:
                    for tup in grep_tuple:
                        tup = [int(item) for item in tup.split(', ')]
                        i = tup[0]
                        i2 = tup[1]
                        i3 = tup[2]
                        deobf_list.append(XenoDecrypt.decrypt(i, i2, i3, arr))

                # Check % match with list of constantsStrings
                with open(classFile_path, 'r', encoding='iso-8859-1') as file:
                    match = []
                    # If file originally contains obfuscated strings, check for match of constantsStrings against the deobfuscated strings
                    if deobf_list:
                        for string in constantsStrings:
                            if string in deobf_list:
                                match.append(True)
                                matched_strings.append(string)
                            else:
                                match.append(False)
                        deobf_allClasses[className] = deobf_list
                    # Else, check for match of constantsStrings against the file itself
                    else:
                        fileStrings = file.read()
                        for string in constantsStrings:
                            if string in fileStrings:
                                match.append(True)
                                matched_strings.append(string)
                            else:
                                match.append(False)
                        file.close()
                percentMatch = sum(match) / len(match)
                if percentMatch >= 0.75:
                    if "family" not in file_details:
                        file_details["family"] = "xenomorph"

                # Get domain names
                regex_domainName = r'"((?!-))(xn--)?[a-z0-9][a-z0-9_-]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})"'
                regex = f'Arrays.asList\\({regex_domainName}(, {regex_domainName})*\\)'

                grep_domainNames = self.grep('-rPo', regex, classFile_path, 0)
                grep_domainNames = grep_domainNames.split('\n')
                for item in grep_domainNames:
                    if item.strip():
                        if re.search('"(.*)"', item) is not None:
                            domainList = re.search('"(.*)"', item).group(1).split(', ')
                            for domain in domainList:
                                if domain.strip():
                                    if domain not in domainNames:
                                        domainNames.append(domain.replace('"', ''))

        file_details["domain_names"] = domainNames
        file_details["matched_strings"] = matched_strings

        deobf_allClasses_keys = list(deobf_allClasses.keys())
        for i in range(len(deobf_allClasses_keys)):
            file_details["deobfuscated strings ({0})".format(deobf_allClasses_keys[i])] = deobf_allClasses[deobf_allClasses_keys[i]]

        return file_details