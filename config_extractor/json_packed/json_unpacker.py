import json

import subprocess
import re
import os
import traceback

from karton.core import Task, Resource
from json_packed.json_deobfuscator import JsonDeobfuscator

PATH = os.path.dirname(os.path.abspath(__file__))

class JsonUnpacker():
    """
    Extracts deobfuscated strings from APK files packed by JSON-Packer.
    Unpack the APK file.
    """

    def read_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                file_content = file.read()
                return file_content
        except FileNotFoundError:
            print(f"[JSON UNPACKER] The file at {file_path} was not found.")

    def process(self, task):
        json_packed_decrypted = False

        # Get apk/dex file 
        apkFile_path = task['payload']['root_parent_path']
        apkFile_content = self.read_file(apkFile_path)

        # Get folder path
        folder_path = task['payload']['folder_path']

        # Get apk sha256 hash
        apk_sha256 = task['payload']['apk_sha256']

        # -----------------  START OF JSON UNPACKER  ----------------- #

        # run python file jsondeobfuscator.py
        # check if file is packed by json packer, then whether strings are obfuscated
        # obtain deobfuscated strings
        file_details = {}
        zipFile_content = bytes()
        try:
            print(f"[JSON UNPACKER] Checking if {apkFile_path} is packed by JSON Packer, then unpack it...")
            file_details = JsonDeobfuscator().process(folder_path)

        except Exception as e:
            print("  [-] Error when running json_deobfuscator.py...")
            print(type(e).__name__, ":", e)
            print(traceback.format_exc())

        jsonFilename = ""

        # if file is packed, unpack it
        if "json_packer" in file_details:
            if file_details["json_packer"] == "True":
                decryptionKey = file_details["key"][0]
                for item in file_details["strings"]:
                    if item.strip() and ".json" in item:
                        jsonFilename = item

                if jsonFilename:
                    jadxDecompiledPath = os.path.join(folder_path, "jadx-decompiled")
                    jsonPath = os.path.join(jadxDecompiledPath, f"resources/assets/{jsonFilename}")

                    newapk_path = os.path.join(folder_path, "newapk")
                    os.makedirs(newapk_path, exist_ok=True)
                    if os.path.exists(jsonPath):
                        try:
                            print(f"[JSON UNPACKER] {apkFile_path} is packed by JSON Packer. Unpacking...")
                            OUT_PATH = os.path.join(newapk_path, "newapk.zip")
                            p = subprocess.Popen(["python3", "json_packed/jsondecrypt.py", "-i", jsonPath, "-o", OUT_PATH, "-k", decryptionKey], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            output, error = p.communicate()
                            
                            subdirs = os.listdir(newapk_path)    # ['newapk.zip']
                            if len(subdirs) == 1 and "newapk.zip" in subdirs:   # check if decryption succeeded based on dirs produced (orig_apk folder, newapk.zip)
                                print(f"  [-] Successful decryption of {apkFile_path}")

                                # get zip file bytes
                                with open(OUT_PATH, 'rb') as f:
                                    zipFile_content = f.read()
                                    f.close()
                            else:
                                raise Exception
                        except Exception as e:
                            print("  [-] Error when running jsondecrypt.py...")
                            print(type(e).__name__, ":", e)
                            print(traceback.format_exc())
                    else:
                        print(f"[JSON UNPACKER] Unable to unpack file. JSON Path {jsonPath} does not exist.")
                else:
                    print("[JSON UNPACKER] Unable to unpack file. Unable to find JSON file.")

        # -----------------  END OF JSON UNPACKER  ----------------- #

        if zipFile_content:
            task = Task(
                {
                    "type": "sample",
                    "stage": "analyzed",
                    "out": "json-unpacker",
                },
                payload={
                    "root_parent_path": task['payload']['root_parent_path'],
                    "folder_path": folder_path,
                    "newapk_path": newapk_path,
                    "decrypted_zipPath": OUT_PATH,
                    "apk_sha256": apk_sha256,
                    "tags": [
                        "file-type:apk",
                        "dropped-payload-file",
                        "feed:json-unpacker",
                        "json_packer-strings",
                    ],
                    "json_unpacker": file_details,
                }
            )

            json_packed_decrypted = True
        else:
            task = Task(
                {
                    "type": "sample",
                    "stage": "analyzed",
                },
                payload={
                    "root_parent_path": task['payload']['root_parent_path'],
                    "folder_path": folder_path,
                    "apk_sha256": apk_sha256,
                    "json_unpacker": file_details,
                    "tags": [
                        "file-type:apk"
                    ]
                }
            )
            print("[JSON UNPACKER] File is not packed by JSON-Packer.")

        json_task = json.loads(str(task))
        return json_packed_decrypted, json_task