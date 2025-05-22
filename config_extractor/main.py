import argparse

import os
import json
from get_file_type import GetFileTypes
from apk_extractor import ApkExtractor
from json_packed.json_unpacker import JsonUnpacker
from xenomorph_config.xenomorph import Xenomorph

class Test():
    def process(self, file_path):
        file_type, task = GetFileTypes().process(file_path)
        print("----------------------------------------------------------------------------------------------")

        if ('dex' in file_type) or ('apk' in file_type):
            success, json_task = ApkExtractor().process(task, file_path)
            print("----------------------------------------------------------------------------------------------")

            if success == True:
                json_packed_decrypted, json_task = JsonUnpacker().process(json_task)
                print("----------------------------------------------------------------------------------------------")

                if json_packed_decrypted == True:
                    decrypted_zipPath = json_task['payload']['decrypted_zipPath']
                    newapk_path = json_task['payload']['newapk_path']
                    json_unpacker_dict = json_task['payload']['json_unpacker']

                    success, json_task = ApkExtractor().process(json_task, decrypted_zipPath)
                    print("----------------------------------------------------------------------------------------------")

                    if success == True:
                        # jsonpacker-packed
                        json_task = Xenomorph().process(json_task, newapk_path, decrypted_zipPath, json_unpacker_dict)
                        print("----------------------------------------------------------------------------------------------")
                        
                        try:
                            # writing to a JSON file
                            with open("output.json", "w") as json_file:
                                json.dump(json_task, json_file, indent=4)
                                print(f"Results saved to {os.path.abspath("output.json")}")
                        except:
                            print(f"Error occurred when writing results to {os.path.abspath("output.json")}")
                        finally:
                            if "xenomorph" in json_task['payload'].keys():
                                # xeno
                                result = \
f"""
APK SHA256:         {json_task['payload']['apk_sha256']}
Output dir:         {json_task['payload']['folder_path']}

JsonPacker-packed:  {json_task['payload']['json_unpacker']['json_packer']}
Decryption key:     {json_task['payload']['json_unpacker']['key']}
Decrypted APK dir:  {json_task['payload']['newapk_path']}
Obfuscated strings: {json_task['payload']['json_unpacker']['obfuscated_strings']}, {json_task['payload']['json_unpacker']['strings']}

Xenomorph family:   {json_task['payload']['family-xenomorph']}
Domain names:       {json_task['payload']['xenomorph']['domain_names']}
Matched strings:    {json_task['payload']['xenomorph']['matched_strings']}
"""
                            else:
                                # non-xeno
                                result = \
f"""
APK SHA256:         {json_task['payload']['apk_sha256']}
Output dir:         {json_task['payload']['folder_path']}

JsonPacker-packed:  {json_task['payload']['json_unpacker']['json_packer']}
Decryption key:     {json_task['payload']['json_unpacker']['key']}
Decrypted APK dir:  {json_task['payload']['newapk_path']}
Obfuscated strings: {json_task['payload']['json_unpacker']['obfuscated_strings']}, {json_task['payload']['json_unpacker']['strings']}

Xenomorph family:   {json_task['payload']['family-xenomorph']}
"""

                            print(result)

                else:
                    json_unpacker_dict = json_task['payload']['json_unpacker']
                    success, json_task = ApkExtractor().process(json_task, file_path)
                    print("----------------------------------------------------------------------------------------------")

                    if success == True:
                        # non-jsonpacker-packed
                        json_task = Xenomorph().process(json_task, json_unpacker_dict)
                        print("----------------------------------------------------------------------------------------------")
                        
                        try:
                            # writing to a JSON file
                            with open("output.json", "w") as json_file:
                                json.dump(json_task, json_file, indent=4)
                                print(f"Results saved to {os.path.abspath("output.json")}")
                        except:
                            print(f"Error occurred when writing results to {os.path.abspath("output.json")}")
                        finally:
                            if "xenomorph" in json_task['payload'].keys():
                                # xeno
                                result = \
f"""
APK SHA256:         {json_task['payload']['apk_sha256']}
Output dir:         {json_task['payload']['folder_path']}

JsonPacker-packed:  {json_task['payload']['json_unpacker']['json_packer']}

Xenomorph family:   {json_task['payload']['family-xenomorph']}
Domain names:       {json_task['payload']['xenomorph']['domain_names']}
Matched strings:    {json_task['payload']['xenomorph']['matched_strings']}
"""
                            else:
                                # non-xeno
                                result = \
f"""
APK SHA256:         {json_task['payload']['apk_sha256']}
Output dir:         {json_task['payload']['folder_path']}

Xenomorph family:   {json_task['payload']['family-xenomorph']}
JsonPacker-packed:  {json_task['payload']['json_unpacker']['json_packer']}
"""

                            print(result)

        else:
            print("File is not APK/DEX file.")

if __name__ == "__main__":
    description = \
r"""   _  __ ____ _  __ ____   __  ___ ____   ___   ___   __ __  _____ ____   _  __ ____ ____ _____
  | |/_// __// |/ // __ \ /  |/  // __ \ / _ \ / _ \ / // / / ___// __ \ / |/ // __//  _// ___/
 _>  < / _/ /    // /_/ // /|_/ // /_/ // , _// ___// _  / / /__ / /_/ //    // _/ _/ / / (_ / 
/_/|_|/___//_/|_/ \____//_/  /_/ \____//_/|_|/_/   /_//_/  \___/ \____//_/|_//_/  /___/ \___/  

This script decompiles APK/DEX files, detects and unpacks files packed by JSON-Packer, and extracts Xenomorph configuration.

Usage: python main.py <file path>
----------------------------------------------------------------------------------------------"""
    print(description)

    parser = argparse.ArgumentParser()
    parser.add_argument("file_path", type=str, help="File path")

    args = parser.parse_args()
    file_path = os.path.abspath(args.file_path)

    Test().process(file_path)