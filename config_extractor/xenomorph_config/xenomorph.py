import hashlib

import json

import re
import os
import shutil
import traceback

from karton.core import Task, Resource
from xenomorph_config.xeno_analyze import XenoAnalyze

PATH = os.path.dirname(os.path.abspath(__file__))

class Xenomorph():
    """
    Config extractor for Xenomorph.
    """

    def get_file_hash(self, file_path):
        try:
            hash_func = hashlib.new("sha256")
            with open(file_path, 'rb') as file:
                while chunk := file.read(8192):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except FileNotFoundError:
            print(f"[XENOMORPH] The file at {file_path} was not found.")

    def read_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                file_content = file.read()
                return file_content
        except FileNotFoundError:
            print(f"[XENOMORPH] The file at {file_path} was not found.")
    
    def process(self, *args):
        # jsonpacker-packed
        if len(args) == 4:
            task = args[0]
            newapk_path = args[1]
            decrypted_zipPath = args[2]
            json_unpacker_dict = args[3]
            # Get apk/dex file 
            apkFile_path = task['payload']['root_parent_path']
            apkFile_content = self.read_file(apkFile_path)

            # Get apk sha256 hash
            apk_sha256 = task['payload']['apk_sha256']

            # -----------------  START OF XENOMORPH  ----------------- #

            # Get decrypted zip file
            decrypted_zipContent = self.read_file(decrypted_zipPath)

            # get zip file containing decrypted apk file, unzip it
            try:
                print("[XENOMORPH] Unzipping decrypted apk file...")
                with open(decrypted_zipPath, 'rb') as f:
                    shutil.unpack_archive(decrypted_zipPath, newapk_path)
                    os.remove(decrypted_zipPath)
                    print("  [-] Successful unzipping of file")
            except Exception as e:
                print("  [-] Error during unzipping of file...")
                print(type(e).__name__, ":", e)
                print(traceback.format_exc())

            # get decrypted apk file name
            file_details = {}
            print("[XENOMORPH] Analyze decrypted apk file...")
            if len(os.listdir(newapk_path)) == 2:   # ['decrypted_file', 'jadx-decompiled'] - decrypted file and decompiled file folder
                for item in os.listdir(newapk_path):
                    item_path = os.path.join(newapk_path, item)
                    if os.path.isfile(item_path):
                        decrypted_apkFilePath = item_path
                    else:
                        decrypted_apkDecompiledPath = item_path
                    
                file_details = XenoAnalyze().setFileDetails_dropped(decrypted_apkDecompiledPath, decrypted_apkFilePath)
            else:
                print(f"  [-] Unable to decrypt apk, unexpected number of files in {newapk_path}")

            # -----------------  END OF XENOMORPH  ----------------- #

            xeno_dict = {}
            if not all(isinstance(v, list) and not v for v in file_details.values()):
                print("  [-] Successfully obtained Xenomorph config")
                if "family" in file_details:
                    file_details_keys = list(file_details.keys())

                    for i in range(len(file_details_keys)):
                        values = file_details[file_details_keys[i]]
                        if type(values) != list:
                            values = [values]

                        # Malware family
                        if file_details_keys[i] == "family":
                            xeno_dict['family'] = values

                        # Deobfuscated strings found in file.
                        elif "deobfuscated strings" in file_details_keys[i]:
                            xeno_dict[file_details_keys[i]] = values

                        # Strings found in file that match strings found in Xenomorph. Includes already deobfuscated strings and plaintext strings.
                        elif file_details_keys[i] == "matched_strings":
                            xeno_dict['matched_strings'] = values

                        # Possible domain names found in file.
                        elif file_details_keys[i] == "domain_names":
                            xeno_dict['domain_names'] = values

            if xeno_dict:
                task = Task(
                        {
                            "type": "sample",
                            "stage": "analyzed",
                            "out": "xenomorph",
                        },
                        payload={
                            "root_parent_path": task['payload']['root_parent_path'],
                            "folder_path": task['payload']['folder_path'],
                            "apk_sha256": apk_sha256,
                            "newapk_path": newapk_path,
                            "decrypted_zipPath": decrypted_zipPath,
                            "tags": [
                                "feed:xenomorph",
                                "xenomorph-config",
                                "family-xenomorph:True"
                            ],
                            "family-xenomorph": True,
                            "xenomorph": xeno_dict,
                            "json_unpacker": json_unpacker_dict,
                        }
                    )
            else:
                print("[XENOMORPH] File is not in Xenomorph family.")
                task = Task(
                        {
                            "type": "sample",
                            "stage": "analyzed",
                            "out": "xenomorph",
                        },
                        payload={
                            "root_parent_path": task['payload']['root_parent_path'],
                            "folder_path": task['payload']['folder_path'],
                            "apk_sha256": apk_sha256,
                            "newapk_path": newapk_path,
                            "decrypted_zipPath": decrypted_zipPath,
                            "tags": [
                                "family-xenomorph:False"
                            ],
                            "family-xenomorph": False,
                            "json_unpacker": json_unpacker_dict,
                        }
                    )
            
            json_task = json.loads(str(task))
            return json_task
        
        # non-jsonpacker-packed
        elif len(args) == 2:
            task = args[0]
            json_unpacker_dict = args[1]

            # Get apk/dex file 
            apkFile_path = task['payload']['root_parent_path']
            apkFile_content = self.read_file(apkFile_path)

            # Get apk sha256 hash
            apk_sha256 = task['payload']['apk_sha256']

            # -----------------  START OF XENOMORPH  ----------------- #

            # get decrypted apk file name
            file_details = {}
            print("[XENOMORPH] Analyze apk file...")
            folder_path = task['payload']['folder_path']
            if len(os.listdir(folder_path)) == 2:   # ['apkFile', 'jadx-decompiled'] - apk file and decompiled file folder
                for item in os.listdir(folder_path):
                    item_path = os.path.join(folder_path, item)
                    if os.path.isfile(item_path):
                        apkFilePath = item_path
                    else:
                        apkDecompiledPath = item_path
                    
                file_details = XenoAnalyze().setFileDetails_dropped(apkDecompiledPath, apkFilePath)
            else:
                print(f"  [-] Unable to decrypt apk, unexpected number of files in {folder_path}")

            # -----------------  END OF XENOMORPH  ----------------- #

            xeno_dict = {}
            if not all(isinstance(v, list) and not v for v in file_details.values()):
                print("  [-] Successfully obtained Xenomorph config")
                if "family" in file_details:
                    file_details_keys = list(file_details.keys())

                    for i in range(len(file_details_keys)):
                        values = file_details[file_details_keys[i]]
                        if type(values) != list:
                            values = [values]

                        # Malware family
                        if file_details_keys[i] == "family":
                            xeno_dict['family'] = values

                        # Deobfuscated strings found in file.
                        elif "deobfuscated strings" in file_details_keys[i]:
                            xeno_dict[file_details_keys[i]] = values

                        # Strings found in file that match strings found in Xenomorph. Includes already deobfuscated strings and plaintext strings.
                        elif file_details_keys[i] == "matched_strings":
                            xeno_dict['matched_strings'] = values

                        # Possible domain names found in file.
                        elif file_details_keys[i] == "domain_names":
                            xeno_dict['domain_names'] = values

            if xeno_dict:
                task = Task(
                        {
                            "type": "sample",
                            "stage": "analyzed",
                            "out": "xenomorph",
                        },
                        payload={
                            "root_parent_path": task['payload']['root_parent_path'],
                            "folder_path": task['payload']['folder_path'],
                            "apk_sha256": apk_sha256,
                            "tags": [
                                "feed:xenomorph",
                                "xenomorph-config",
                                "family-xenomorph:True"
                            ],
                            "family-xenomorph": True,
                            "xenomorph": xeno_dict,
                            "json_unpacker": json_unpacker_dict,
                        }
                    )
            else:
                print("[XENOMORPH] File is not in Xenomorph family.")
                task = Task(
                        {
                            "type": "sample",
                            "stage": "analyzed",
                            "out": "xenomorph",
                        },
                        payload={
                            "root_parent_path": task['payload']['root_parent_path'],
                            "folder_path": task['payload']['folder_path'],
                            "apk_sha256": apk_sha256,
                            "tags": [
                                "family-xenomorph:False"
                            ],
                            "family-xenomorph": False,
                            "json_unpacker": json_unpacker_dict,
                        }
                    )
                
            json_task = json.loads(str(task))
            return json_task