import os
import subprocess
from karton.core import Task, Resource

import json
import traceback

PATH = os.path.dirname(os.path.abspath(__file__))

class ApkExtractor():
    """
    Extracts files from apk type files.
    """

    def read_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                file_content = file.read()
                return file_content
        except FileNotFoundError:
            print(f"[APK EXTRACTOR] The file at {file_path} was not found.")

    def process(self, task, apkFile_path):
        success = False

        # Get apk/dex file
        apkFile_content = self.read_file(apkFile_path)

        # Get apk sha256 hash
        if "apk_sha256" in task['payload']:
            apk_sha256 = task['payload']['apk_sha256']
        else:
            apk_sha256 = task['payload']['sha256']

        # -----------------  START OF APK EXTRACTOR  ----------------- #

        try:
            # jadx
            print(f"[APK EXTRACTOR] {apkFile_path} is an APK file. Extracting files...")
            TOOL = 'jadx'
            OUTPUT = '-d'
            if "newapk_path" in task['payload']:
                OUT_PATH = os.path.join(task['payload']['newapk_path'], "jadx-decompiled")
            else:
                OUT_PATH = os.path.join(os.getcwd(), task['payload']['folder_path'], "jadx-decompiled")
            os.makedirs(OUT_PATH, exist_ok=True)
            print(f"  [-] Creating dir {OUT_PATH}...")
            IN_PATH = apkFile_path
            p = subprocess.Popen([TOOL, OUTPUT, OUT_PATH, apkFile_path], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = p.communicate()

            subdirs = os.listdir(OUT_PATH)
            if len(subdirs) == 0:   # check if decompilation succeeded based on dirs produced (resources, sources)
                raise Exception
            else:
                print(f"  [-] Successful decompilation of {apkFile_path}")
                success = True

        except Exception as e:
            print("  [-] Error during decompilation with jadx...")
            print(type(e).__name__, ":", e)
            print(traceback.format_exc())

        # -----------------  END OF APK EXTRACTOR  ----------------- #

        task = Task(
            {
                "type": "sample",
                "stage": "analyzed",
                "out": "apk-extractor",
            },
            payload={
                "root_parent_path": task['payload']['root_parent_path'],
                "folder_path": task['payload']['folder_path'],
                "parent_path": apkFile_path,
                "apk_sha256": apk_sha256,
                "tags": [
                    "file-type:zip",
                    "decompiled-files:jadx",
                ],
            }
        )

        json_task = json.loads(str(task))
        return success, json_task