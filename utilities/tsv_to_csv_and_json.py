# This tool reads a TSV file from the indicator ID and writes CSV and
# JSON files in this repo's schema
# NOTE: This file is used for repo management, not for malware/threat detection
# Copyright (c) Meta Platforms, Inc. and its affiliates.

import csv, json, os.path, pathlib, re, sys

if len(sys.argv) < 2:
	print("Must supply indicator ID")
	exit(1)

id = sys.argv[1]
data = []
tsv_path = str(pathlib.Path(__file__).parent.resolve()) + "/../indicators/tsv/" + id + ".tsv"
csv_path = str(pathlib.Path(__file__).parent.resolve()) + "/../indicators/csv/" + id + ".csv"
json_path = str(pathlib.Path(__file__).parent.resolve()) + "/../indicators/json/" + id + ".json"

if not re.search("^[a-zA-Z0-9\-_]+$", id):
	print("ID must match ^[a-zA-Z0-9\-_]+$")
	exit(1)

with open(tsv_path) as f:
	for line in f:
		if line.startswith("indicator_type"):
			continue
		indicator_type, indicator_value, comment, ds = line.rstrip().split("\t")
		data.append({
			"indicator_type" : indicator_type,
			"indicator_value" : indicator_value,
			"comment" : comment,
			"ds" : ds
		})

if not os.path.isfile(json_path):
	with open(json_path, "w") as f:
		f.write(json.dumps(data, indent=4))
	print("Created JSON File")

if not os.path.isfile(csv_path):
	with open(csv_path, "w") as f:
		field_names = ["indicator_type", "indicator_value", "comment", "ds"]
		csv_writer = csv.DictWriter(f, fieldnames=field_names, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
		csv_writer.writeheader()
		for row in data:
			csv_writer.writerow(row)
	print("Created CSV File")
