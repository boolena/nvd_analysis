import gzip
from io import BytesIO
import requests
import json


NVD_CVE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"


def run():

    mappings = {}
    cve_list = []

    mappings_file = "mappings_all.json"
    statistics_file = "statistics.txt"

    for year in range(2002, 2023):

        print("Checking {year}".format(year=year))

        counter_and_year = 0

        # Download the file
        url = NVD_CVE_URL.format(year=year)
        resp = requests.get(url).content

        # Parse the XML elements
        raw = gzip.GzipFile(fileobj=BytesIO(resp)).read()
        del resp
        items = json.loads(raw.decode("utf-8"))["CVE_Items"]
        del raw

        for item in items:
            for node in item["configurations"]["nodes"]:
                if node["operator"] == "AND":
                    if item["cve"]["CVE_data_meta"]["ID"] not in cve_list:
                        cve_list.append(str(item["cve"]["CVE_data_meta"]["ID"]))
                        counter_and_year = counter_and_year + 1

                    if len(node["children"]) == 0:
                        for match in node["cpe_match"]:
                            if match["vulnerable"]:
                                if match["cpe23Uri"] not in mappings.keys():
                                    mappings[match["cpe23Uri"]] = [item["cve"]["CVE_data_meta"]["ID"]]
                                else:
                                    mappings[match["cpe23Uri"]].append(item["cve"]["CVE_data_meta"]["ID"])

                    else:
                        for child in node["children"]:
                            for cpe in child["cpe_match"]:
                                if cpe["vulnerable"]:
                                    if cpe["cpe23Uri"] not in mappings.keys():
                                        mappings[cpe["cpe23Uri"]] = [item["cve"]["CVE_data_meta"]["ID"]]
                                    else:
                                        mappings[cpe["cpe23Uri"]].append(item["cve"]["CVE_data_meta"]["ID"])

        with open(statistics_file, 'a') as file:
            file.write("___{year}___\n".format(year=year))
            file.write("CVEs insgesamt: " + str(len(items)) + "\n")
            file.write("CVEs mit einem \"AND\"-Operator: " + str(counter_and_year) + "\n")
            file.write("\n")

    # Sort and save mappings
    sorted_mappings = sorted(mappings.items(), key=lambda x: len(x[1]), reverse=True)
    with open(mappings_file, "w") as m_result:
        json.dump(sorted_mappings, m_result)


if __name__ == '__main__':
    run()




