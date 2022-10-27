# Python tool to walk a directory and subdirectories and convert the test files to the new format
# This will take test.json and convert it to test.yaml

import os
import json
import yaml
import argparse

def convert_test_file(test_file):
    with open(test_file, 'r') as f:
        data = json.load(f)
    with open(test_file.replace('.json', '.yml'), 'w') as f:
        yaml.dump(data, f, sort_keys=False)
    os.remove(test_file)

# Walk the directory and convert all test.json files to test.yaml
def convert_test_files(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".json"):
                test_file = os.path.join(root, file)
                convert_test_file(test_file)


def main():
    parser = argparse.ArgumentParser(description='Convert test files from json to yaml')
    parser.add_argument('directory', help='Directory to convert')
    args = parser.parse_args()
    convert_test_files(args.directory)


if __name__ == "__main__":
    main()
