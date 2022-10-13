# This tool reads a TSV file from the indicator ID and writes CSV and
# JSON files in this repo's schema
# NOTE: This file is used for repo management, not for malware/threat detection
# Copyright (c) Meta Platforms, Inc. and affiliates

import csv, json, os.path, pathlib, re, sys, uuid

import cybox.helper
from cybox.common.hashes import Hash
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI

import mixbox.idgen

from stix.core import STIXPackage
from stix.indicator.indicator import Indicator
from stix.report import Report
from stix.report.header import Header

mixbox.idgen.set_id_namespace(mixbox.idgen.Namespace("https://meta.com/stix", "meta_stix", ""))

if len(sys.argv) < 2:
	print("Must supply indicator ID")
	exit(1)

id = sys.argv[1]
data = []
tsv_path = str(pathlib.Path(__file__).parent.resolve()) + "/../indicators/tsv/" + id + ".tsv"
csv_path = str(pathlib.Path(__file__).parent.resolve()) + "/../indicators/csv/" + id + ".csv"
json_path = str(pathlib.Path(__file__).parent.resolve()) + "/../indicators/json/" + id + ".json"
stix_1_path = str(pathlib.Path(__file__).parent.resolve()) + "/../indicators/stix1/" + id + ".xml"
stix_2_path = str(pathlib.Path(__file__).parent.resolve()) + "/../indicators/stix2/" + id + ".json"

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

if not os.path.isfile(stix_1_path):
	stix_package = STIXPackage()
	stix_report = Report()
	stix_report.header = Header()
	stix_report.header.description = "Meta Threat Detection Package for {}".format(id)

	for row in data:
		indicator_type = row["indicator_type"]
		indicator_id = uuid.uuid4()
		indicator = Indicator()

		if indicator_type == "url" or indicator_type == "telegram_url" or indicator_type == "phishing_url" or indicator_type == "cib_url":
			indicator.id_ = "{}:url-{}".format(id, indicator_id)
			indicator.title = row["comment"] + " ({})".format(indicator_type)
			indicator.add_indicator_type("URL Watchlist")

			url = URI()
			url.value = row["indicator_value"]
			url.type_ =  URI.TYPE_URL
			url.condition = "Equals"
			indicator.add_observable(url)
			stix_package.add_indicator(indicator)
		elif indicator_type == "domain_name":
			indicator.id_ = "{}:domain_name-{}".format(id, indicator_id)
			indicator.title = row["comment"]
			indicator.add_indicator_type("Domain Watchlist")

			domain = DomainName()
			domain.value = row["indicator_value"]
			domain.value.condition = "Equals"
			indicator.add_observable(domain)
			stix_package.add_indicator(indicator)
		elif indicator_type == "ip":
			indicator.id_ = "{}:ip-{}".format(id, indicator_id)
			indicator.title = row["comment"]
			indicator.add_indicator_type("IP Watchlist")

			address = Address(address_value=row["indicator_value"], category=Address.CAT_IPV4)
			address.condition = "Equals"
			indicator.add_observable(address)
			stix_package.add_indicator(indicator)
		elif indicator_type == "md5" or indicator_type == "sha256":
			indicator.id_ = "{}:hash-{}".format(id, indicator_id)
			indicator.title = row["comment"] + " ({})".format(indicator_type)
			indicator.add_indicator_type("File Hash Watchlist")

			file_object = File()
			hash = Hash(hash_value=row["indicator_value"], type_=indicator_type.upper())
			file_object.add_hash(hash)
			file_object.condition = "Equals"
			indicator.add_observable(file_object)
			stix_package.add_indicator(indicator)
		elif indicator_type == "android_package_name" or indicator_type == "ios_app_id":
			indicator.id_ = "{}:hash-{}".format(id, indicator_id)
			indicator.title = row["comment"] + " ({})".format(indicator_type)
			indicator.add_indicator_type("File Hash Watchlist")

			file_object = File()
			file_object.file_name = row["indicator_value"]
			file_object.condition = "Equals"
			indicator.add_observable(file_object)
			stix_package.add_indicator(indicator)
		else:
			print("Can't process {}".format(row))

	with open(stix_1_path, "w") as f:
		f.write(stix_package.to_xml(pretty=True, encoding=None))
	print("Created STIX v1 File")
