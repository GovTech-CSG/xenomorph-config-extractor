import sys
import os
import shutil
import subprocess

import traceback

class JsonDeobfuscator():
    # grep
    def grep(self, OPTIONS, STRING_, DIR):
        TOOL = 'grep'

        try:
            print(f"  [-] Attempting to grep '{STRING_}' from files...")
            p = subprocess.Popen([TOOL, OPTIONS, STRING_, DIR], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = p.communicate()
            if output.strip():
                pass
            else:
                print("  Item was not found")
        except Exception as e:
            print(f"    [-] Error during grep '{STRING_}'...")
            print(type(e).__name__, ":", e)
            print(traceback.format_exc())
        print(f"    [-] Successful grep '{STRING_}'")
        return(output.decode('iso-8859-1'))

    def jsonDeobfuscator(self, folder_path):
        result = ""
        class_deobfStr = []
        funcs_deobfStr = []
        funcsToAdd_deobfStr = []
        class_decryptionKey = []
        func_decryptionKey = []
        funcsToAdd_decryptionKey = []
        deobfuscatedStrings = []
        decryptionKey = []

        # grep for class file that contains DexClassLoader
        grep_DexClassLoader = self.grep('-r', "DexClassLoader", os.path.abspath(folder_path))

        # grep for class file that contains name of encrypted json file
        grep_attachBaseContext = self.grep('-r', "attachBaseContext", os.path.abspath(folder_path))   # e.g., /path/to/sources/com/great/calm/NCmSxNwTn.java
        
        # ## Check if packed by JSON Packer #################################################################################################################

        # if both grep_DexClassLoader and grep_attachBaseContext are not empty, we can confirm this is likely the same pattern of JSON Packer
        # the strings may or may not be obfuscated
        if grep_DexClassLoader.strip() and grep_attachBaseContext.strip():
            
            # proceed with deobfuscating
            grep_attachBaseContext = grep_attachBaseContext.split('\n')
            for i in range(len(grep_attachBaseContext)):
                if grep_attachBaseContext[i].strip() and ":" in grep_attachBaseContext[i]:  # ignore empty and "Binary file /some/path/ matches"
                    item = grep_attachBaseContext[i].split(':')[0]
                    if item:
                        if item not in class_deobfStr:
                            class_deobfStr.append(item)

            # ## Check if only 1 class file found #################################################################################################################

            # if only 1 class file found, we can confirm this is likely the same pattern of JSON Packer
            # proceed to get the string obfuscation functions
            if len(class_deobfStr) == 1:
                # grep for lines that start with String in the above class file (possible var with encryption func)
                # e.g., String WMkXpTgRtInLkJzJdFlQgYwQiUaFxGyJkIoXySfPuNbAbTu = pulseinsane(new String[98]);
                grep_linesContainString = self.grep('-rE', r"^\s{4}String ", os.path.abspath(class_deobfStr[0].strip()))

                # ## Check if strings are obfuscated #################################################################################################################

                # to confirm if strings are obfuscated, check for the presence of some plaintext strings
                # if not present, strings are obfuscated
                if "Dynamic" not in grep_linesContainString.strip() or ".json" not in grep_linesContainString.strip():

                    grep_linesContainString = grep_linesContainString.split('\n')
                    for i in range(len(grep_linesContainString)):
                        if grep_linesContainString[i].strip():
                            item = grep_linesContainString[i].split('= ')[1].split('(')[0]
                            if item:
                                if item not in funcs_deobfStr:    # e.g., pulseinsane, canoelady, crytoe
                                    funcs_deobfStr.append(item)

                    # grep for functions that only return a function (returned func is possible encryption func)
                    # e.g., static String pulseinsane(String[] strArray) { return defyoff(); }
                    # e.g., static String acttwo(String[] strArray) { return changeman(); }
                    grep_funcsOnlyReturnFunc = self.grep('-rEzo', r"static String [[:print:]]+\ {[[:space:]]+return [[:print:]]+[[:space:]]+}[[:space:]]", os.path.abspath(class_deobfStr[0].strip()))
                    
                    grep_funcsOnlyReturnFunc = grep_funcsOnlyReturnFunc.split('\n')
                    for i in range(1, len(grep_funcsOnlyReturnFunc), 3):
                        if grep_funcsOnlyReturnFunc[i].strip() and "return " in grep_funcsOnlyReturnFunc[i]:
                            item = grep_funcsOnlyReturnFunc[i].split('return ')[1].split('(')[0]    # e.g., defyoff, changeman, ...
                            if item:
                                # check line above to see if item is a returned func called by an obfuscatedStringFunc
                                if grep_funcsOnlyReturnFunc[i-1].split('String ')[1].split('(')[0] in funcs_deobfStr: # e.g., pulseinsane, canoelady, crytoe
                                    funcsToAdd_deobfStr.append(item)    # append only if item is a returned func from an obfuscatedStringFunc 
                                    # e.g., append 'defyoff' because 'pulseinsane(String[] strArray) { return defyoff(); }' and 'String WMkXpTgRtInLkJzJdFlQgYwQiUaFxGyJkIoXySfPuNbAbTu = pulseinsane(new String[98]);'

                    copy_decryptionFunc = ""
                    # copy functions stored in the String var, also in the above class file (possible encryption func)
                    with open(os.path.abspath(class_deobfStr[0].strip()), 'r') as file:
                        fileContent = file.readlines()
                        for i in range(len(fileContent)):
                            if any(item in fileContent[i] for item in funcsToAdd_deobfStr) and "=" not in fileContent[i] and "return" not in fileContent[i]:
                                copying = True
                                openBracket = 1
                                while copying:
                                    copy_decryptionFunc= copy_decryptionFunc+ fileContent[i].strip()
                                    i = i+1
                                    if openBracket == 0:
                                        copying = False
                                    if "}" not in fileContent[i] and "{" in fileContent[i]:
                                        openBracket = openBracket + 1
                                    elif "}" in fileContent[i] and "{" not in fileContent[i] and openBracket > 0:
                                        openBracket = openBracket - 1
                        file.close()

                    # grep location of decryption function of xeno file (diff class file)
                    # e.g., return zRbLxOaPdMbItWu.roomhorse(str, this.UDaFsJgEaNxBtXaTjRgBwNcSeSaCeNsLsOk, this.DBcKnHjGlBgNs); 
                    grep_decryptionKeyClass = self.grep('-rEzo', r"return [[:alpha:]]+.[[:alpha:]]+\(str, this.[[:alpha:]]+, this.[[:alpha:]]+\);", os.path.abspath(class_deobfStr[0].strip()))

                    grep_decryptionKeyClass = grep_decryptionKeyClass.split('\n')
                    decryptionKeyClass_dir = class_deobfStr[0].rsplit("/", 1)[0]
                    for i in range(len(grep_decryptionKeyClass)):
                        if grep_decryptionKeyClass[i].strip():
                            item = grep_decryptionKeyClass[i].split('return ')[1].split('.')[0]
                            if item:
                                # grep the decryption class name in entire directory (due to case sensitivity)
                                grep_decryptionKeyClass_case = self.grep('-rEio', "public class " + item, decryptionKeyClass_dir)

                                grep_decryptionKeyClass_case = grep_decryptionKeyClass_case.split('\n')
                                for i in range(len(grep_decryptionKeyClass_case)):
                                    if grep_decryptionKeyClass_case[i].strip():
                                        item = grep_decryptionKeyClass_case[i].strip().split(':')[0].split('/')[-1]
                                        if item not in class_deobfStr:   # not same as class_deobfStr
                                            if item not in class_decryptionKey: # no duplicates
                                                class_decryptionKey.append(item)

                    # ## Check if only 1 class file found #################################################################################################################

                    # if only 1 class file found, we can confirm this is likely the same pattern of JSON Packer
                    # proceed to get the decryption key
                    if len(class_decryptionKey) == 1:
                        # grep for lines that start with String in the above class file (possible var with decryption key)
                        # e.g., String DWbZtOoUeQtUjGxWsEjRsUoZyCwObXqDfXs = rebuildholiday(new String[98]);
                        decryptionKeyClass_path = decryptionKeyClass_dir + "/" + class_decryptionKey[0].strip()
                        grep_decryptionKeyFunc = self.grep('-rE', r"^\s{4}String ", os.path.abspath(decryptionKeyClass_path))

                        grep_decryptionKeyFunc = grep_decryptionKeyFunc.split('\n')
                        for i in range(len(grep_decryptionKeyFunc)):
                            if grep_decryptionKeyFunc[i].strip():
                                item = grep_decryptionKeyFunc[i].split('= ')[1].split('(')[0]
                                if item:
                                    if item not in func_decryptionKey:
                                        func_decryptionKey.append(item)

                        # if only 1 func found, we can confirm this is likely the same pattern of JSON Packer
                        # proceed to get the decryption key
                        if len(func_decryptionKey) == 1:
                            # grep for functions that only return a function (returned func is possible encryption func)
                            # e.g., static String rebuildholiday(String[] strArray) { return strategyrunway(); }
                            grep_funcsOnlyReturnFunc = self.grep('-rEzo', "static String " + func_decryptionKey[0] + r"[[:print:]]+\ {[[:space:]]+return [[:print:]]+[[:space:]]+}[[:space:]]", os.path.abspath(decryptionKeyClass_path))

                            grep_funcsOnlyReturnFunc = grep_funcsOnlyReturnFunc.split('\n')
                            for i in range(1, len(grep_funcsOnlyReturnFunc), 3):
                                if grep_funcsOnlyReturnFunc[i].strip() and "return " in grep_funcsOnlyReturnFunc[i]:
                                    item = grep_funcsOnlyReturnFunc[i].split('return ')[1].split('(')[0]    # e.g., strategyrunway
                                    if item:
                                        # check line above to see if item is a returned func called by a func in func_decryptionKey
                                        if grep_funcsOnlyReturnFunc[i-1].split('String ')[1].split('(')[0] in func_decryptionKey: # e.g., rebuildholiday
                                            funcsToAdd_decryptionKey.append(item)    # append only if item is a returned func from a func in func_decryptionKey 
                                            # e.g., append 'strategyrunway' because 'rebuildholiday(String[] strArray) { return strategyrunway(); }' and 'String DWbZtOoUeQtUjGxWsEjRsUoZyCwObXqDfXs = rebuildholiday(new String[98]);'


                            copy_decryptionKey = ""
                            # copy functions stored in the String var, also in the above class file (possible encryption func)
                            with open(os.path.abspath(decryptionKeyClass_path), 'r') as file:
                                fileContent = file.readlines()
                                for i in range(len(fileContent)):
                                    if any(item in fileContent[i] for item in funcsToAdd_decryptionKey) and "=" not in fileContent[i] and "return" not in fileContent[i]:
                                        copying = True
                                        openBracket = 1
                                        while copying:
                                            copy_decryptionKey = copy_decryptionKey + fileContent[i].strip()
                                            i = i+1
                                            if openBracket == 0:
                                                copying = False
                                            if "}" not in fileContent[i] and "{" in fileContent[i]:
                                                openBracket = openBracket + 1
                                            elif "}" in fileContent[i] and "{" not in fileContent[i] and openBracket > 0:
                                                openBracket = openBracket - 1
                                file.close()

                    # ## Create newfile.java #################################################################################################################

                    # create file to run the functions and get possible names
                    newapk_path = os.path.join(folder_path, "newapk")
                    os.makedirs(newapk_path, exist_ok=True)

                    new_java = os.path.join(newapk_path, "newfile.java")
                    with open(new_java, "w") as file:
                        callFuncs = ""
                        for i in range(len(funcsToAdd_deobfStr)):
                            callFuncs = callFuncs + f"System.out.println({funcsToAdd_deobfStr[i]}());"   # e.g., defyoff();

                        for i in range(len(funcsToAdd_decryptionKey)):
                            callFuncs = callFuncs + f"System.out.println({funcsToAdd_decryptionKey[i]}());"

                        file.write(f"public class newfile {{ public static void main(String[] args) {{ {callFuncs} }} {copy_decryptionFunc} {copy_decryptionKey} }}")

                    # ## Run newfile.java #################################################################################################################

                    # compile and run the file to obtain decrypted strings, decryption key
                    try:
                        p = subprocess.Popen(["javac", new_java], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        output, error = p.communicate()

                        if "error" in output.decode() or "error" in error.decode():
                            raise Exception
                        else:
                            print("    [-] Successful compile of newfile.java")
                            try:
                                p = subprocess.Popen(['java', "-classpath", newapk_path, "newfile"], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                output, error = p.communicate()
                                
                                if "Error" in output.decode() or "Error" in error.decode():
                                    raise Exception
                                else:
                                    print("    [-] Successful running of newfile")
                                    if output.decode().strip():
                                        result = output.decode().strip()
                            except Exception as e:
                                print("    [-] Error during running of newfile")
                    except Exception as e:
                        print("    [-] Error during javac")

                else:
                    print("  [-] This file does not contain obfuscated strings")

                    # ## Check if only 1 class file found #################################################################################################################

                    # if only 1 class file found, we can confirm this is likely the same pattern of JSON Packer
                    # proceed to get the string obfuscation functions
                    if len(class_deobfStr) == 1:
                        grep_linesContainString = grep_linesContainString.split('\n')
                        for i in range(len(grep_linesContainString)):
                            if grep_linesContainString[i].strip():
                                item = grep_linesContainString[i].split('= "')[1].split('"')[0]
                                if item:
                                    if item not in deobfuscatedStrings:    # e.g., DynamicLib, DynamicOptDex, xxx.json
                                        deobfuscatedStrings.append(item)

                        # grep location of decryption function of xeno file (diff class file)
                        # e.g., return zRbLxOaPdMbItWu.roomhorse(str, this.UDaFsJgEaNxBtXaTjRgBwNcSeSaCeNsLsOk, this.DBcKnHjGlBgNs); 
                        grep_decryptionKeyClass = self.grep('-rEzo', r"return [[:alpha:]]+.[[:alpha:]]+\(str, this.[[:alpha:]]+, this.[[:alpha:]]+\);", os.path.abspath(class_deobfStr[0].strip()))

                        grep_decryptionKeyClass = grep_decryptionKeyClass.split('\n')
                        decryptionKeyClass_dir = class_deobfStr[0].rsplit("/", 1)[0]
                        for i in range(len(grep_decryptionKeyClass)):
                            if grep_decryptionKeyClass[i].strip():
                                item = grep_decryptionKeyClass[i].split('return ')[1].split('.')[0]
                                if item:
                                    # grep the decryption class name in entire directory (due to case sensitivity)
                                    grep_decryptionKeyClass_case = self.grep('-rEio', "public class " + item, decryptionKeyClass_dir)

                                    grep_decryptionKeyClass_case = grep_decryptionKeyClass_case.split('\n')
                                    for i in range(len(grep_decryptionKeyClass_case)):
                                        if grep_decryptionKeyClass_case[i].strip():
                                            item = grep_decryptionKeyClass_case[i].strip().split(':')[0].split('/')[-1]
                                            if item not in class_deobfStr:   # not same as class_deobfStr
                                                if item not in class_decryptionKey: # no duplicates
                                                    class_decryptionKey.append(item)

                        # ## Check if only 1 class file found #################################################################################################################

                        # if only 1 class file found, we can confirm this is likely the same pattern of JSON Packer
                        # proceed to get the decryption key
                        if len(class_decryptionKey) == 1:
                            # grep for lines that start with String in the above class file (possible var with decryption key)
                            # e.g., String DWbZtOoUeQtUjGxWsEjRsUoZyCwObXqDfXs = rebuildholiday(new String[98]);
                            decryptionKeyClass_path = decryptionKeyClass_dir + "/" + class_decryptionKey[0].strip()
                            grep_decryptionKey = self.grep('-rE', r"^\s{4}String ", os.path.abspath(decryptionKeyClass_path))

                            grep_decryptionKey = grep_decryptionKey.split('\n')
                            for i in range(len(grep_decryptionKey)):
                                if grep_decryptionKey[i].strip():
                                    item = grep_decryptionKey[i].split('= "')[1].split('"')[0]
                                    if item:
                                        if item not in decryptionKey:
                                            decryptionKey.append(item)

                    result = deobfuscatedStrings, decryptionKey
        else:
            print("  [-] This file is not packed by JSON Packer")
            
        return result

    def cleanup(self, folder_path):
        newapk_path = os.path.join(folder_path, "newapk")
        if os.path.exists(newapk_path):
            shutil.rmtree(newapk_path)

    def process(self, folder_path):
        file_details = {}

        results = self.jsonDeobfuscator(folder_path)
        if results:
            file_details["json_packer"] = "True"
            if type(results) == tuple: # not obfuscated
                file_details["obfuscated_strings"] = "False"
                stringsList, decryptionKey = results
                file_details["strings"] = stringsList
                file_details["key"] = decryptionKey
            else:
                file_details["obfuscated_strings"] = "True"
                obfuscatedStringsList, decryptionKey = results.rsplit('\n', 1)
                file_details["strings"] = obfuscatedStringsList.split('\n')
                file_details["key"] = [decryptionKey]
        else:
            file_details["json_packer"] = "False"

        self.cleanup(folder_path)
        return file_details