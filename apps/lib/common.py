# !/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import base64
import time
import re
import sys
import random
import requests
import collections
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from tenacity import retry, wait_fixed, stop_after_attempt, before_log
from config import *
from apps import mongo, log

reload(sys)
sys.setdefaultencoding('utf8')
executor = ThreadPoolExecutor(10)
fix_version = {

}

poc = {

}


def timestamp2str(date):
    if date:

        return datetime.fromtimestamp(date).strftime("%Y-%m-%d %H:%M:%S")
    else:
        return ""


def get_header():
    header = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'close',
        'Accept-Encoding': 'gzip, deflate'
    }
    return header


@retry(wait=wait_fixed(7), stop=stop_after_attempt(5))
def retry_get(url, **kwargs):
    log.debug(url)
    return requests.get(url=url, headers=get_header(), **kwargs)


def req(url, user="", pwd=""):
    resp_json = {}
    try:
        if user and pwd:
            session = requests.session()
            session.auth = (user, pwd)

            resp = session.get(url=url, headers=get_header())
        else:
            resp = requests.get(url=url, headers=get_header())

        if resp.status_code == 200:
            resp_json = resp.json()
    except:
        log.exception("req_url:%s" % url)

    return resp_json

##
# Return dataset of the n'th last analysis of given image
##
def get_vuln_trend(fulltag="", n=5):
    final_result = {
        "analyzed_at": [],
        "critical": [],
        "high": [],
        "low": [],
        "medium": [],
        "negligible": [],
        "unknown": []

    }
    try:
        images = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL].find({"fulltag": fulltag}).sort("analyzed_at", -1).limit(n)

        if images.count():
            for i in images:
                final_result["analyzed_at"].insert(0, timestamp2str(i["analyzed_at"]))
                final_result["critical"].insert(0, i["risk"]["critical"])
                final_result["high"].insert(0, i["risk"]["high"])
                final_result["medium"].insert(0, i["risk"]["medium"])
                final_result["low"].insert(0, i["risk"]["low"])
                final_result["negligible"].insert(0, i["risk"]["negligible"])
                final_result["unknown"].insert(0, i["risk"]["unknown"])

    except:
        log.exception("error")

    return final_result


def validate_is_dict(option, value):
    if not isinstance(value, dict):
        raise TypeError("%s must be an instance of dict" % (option,))

##
# Return last analysis of given image
##
def get_last_analysis(fulltag=""):
    #log.debug("get_last_analysis(%s)" % fulltag)
    images_details = {}

    mongo_anchore_result = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL]
    # Find last image analysis
    lastAnalysis = mongo_anchore_result.find_one(filter={"fulltag": fulltag}, sort=[("analyzed_at", -1)])

    if lastAnalysis:
        #log.debug("imageId: %s" % lastAnalysis["imageId"])

        # Construct DTO
        images_details["fulltag"] = lastAnalysis["fulltag"]
        images_details["project_name"] = lastAnalysis["project_name"]
        images_details["total_package"] = {}
        images_details["vulnerabilities"] = lastAnalysis["vulnerabilities"]
        images_details["publisher"] = lastAnalysis["publisher"]

        # TODO : Ensure this aggregate packages of LAST analysis
        total_package_sum = mongo_anchore_result.aggregate([
            {'$match': {'_id': lastAnalysis["_id"]}},
            {"$unwind": "$vulnerabilities"},
            {"$group": {"_id": "$vulnerabilities.package_name", "sum": {"$sum": 1}}},
            {"$sort": {"sum": -1}},
            {"$limit": 10}
        ])
        for i in total_package_sum:
            images_details["total_package"][i["_id"]] = i["sum"]

        images_details["total_risk"] = lastAnalysis["risk"]
    return images_details


def get_pom_file(docker_url=""):
    result = ""
    if docker_url:
        find_result = mongo.conn[MONGO_DB_NAME][MONGO_DEP_COLL].find_one({"docker_url": docker_url})
        if find_result:
            result = base64.b64decode(find_result.get("result", ""))

    return result


##
# Return collection of images grouped by fulltag
##
def get_images():
    final_result = []
    # Get all analysis
    mongo_anchore_result = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL]
    images = mongo_anchore_result.find()
    if images.count():

        # Group by fulltag
        images_analysis = mongo_anchore_result.aggregate([
            # sort DESC
            {"$sort": {"analyzed_at": -1}},   # Null value possible when analysis_failed, but it will appear last
            # then group by fulltag, taking 1st repeting element
            {"$group": {
                "_id": "$fulltag",
                "risk": {"$first": "$risk"},
                "analyzed_at": {"$first": "$analyzed_at"},
                "affected_package_count": {"$first": "$affected_package_count"},
                "imageId": {"$first": "$imageId"},
                "analysis_status": {"$first": "$analysis_status"},
                "publisher": {"$first": "$publisher"}
            }}
        ])

        # Construct DTOs
        for i in images_analysis:
            #log.debug("Image %s, id %s" % (i["_id"], i["imageId"]))
            project_result = {}
            try:

                project_result["affected_package_count"] = i.get("affected_package_count", "")
                project_result["fulltag"] = i["_id"]
                project_result["analyzed_at"] = timestamp2str(i["analyzed_at"])
                project_result["imageId"] = i["imageId"]

                project_result["critical"] = i["risk"]["critical"]
                project_result["high"] = i["risk"]["high"]
                project_result["medium"] = i["risk"]["medium"]
                project_result["low"] = i["risk"]["low"]
                project_result["negligible"] = i["risk"]["negligible"]
                project_result["unknown"] = i["risk"]["unknown"]
                project_result["analysis_status"] = i["analysis_status"]
                project_result["publisher"] = i["publisher"]
                final_result.append(project_result)

            except:
                # TODO : do we sync by imageid or fulltag ?
                executor.submit(sync_data, imageId=i["imageId"], force=True)
                # sync_data(imageId=i["imageId"], force=True)
                log.exception(i)
    return final_result


def get_parents(input_dependency):
    dependency_list = []
    ouput = []
    while True:
        start = input_dependency.find("[INFO] +-")
        if start == -1:
            break
        end = input_dependency.find("[INFO] +-", start + 10)
        dependency_list.append(input_dependency[start:end])
        input_dependency = input_dependency[end:]

    for dependency in dependency_list:

        child_jar = []
        parents_and_version = ""
        parents_jar_name = ""
        group_id = ""
        match_obj = re.findall(r"- (.+):(.+):(.+):(.+):(.+)", dependency)
        if match_obj:
            parents_and_version = ":".join([match_obj[0][1], match_obj[0][3]])
            group_id = match_obj[0][0]
            parents_jar_name = match_obj[0][1]

            child_jar = [x[1] for x in match_obj[1:]]

        if len(child_jar) == 0:
            child_jar = [parents_jar_name]
        else:
            child_jar.append(match_obj[0][1])

        ouput.append({"group_id": group_id, "parents": parents_and_version, "child": child_jar})
    return ouput


def format_version(version, point):
    version_list = version.split(".")
    return ".".join(version_list[:point]) + "."


def get_version(group_id, package, image_id):
    package_version = {
        "last_version": "",
        "same_version": ""
    }
    package_name, current_package_version = package.split(":")
    if current_package_version.count(".") in [2, 3]:  # 8.0.28 or 2.2.2.RELEASE

        current_package_version = format_version(current_package_version, 2)

    elif current_package_version.count("-") == 1:
        current_package_version = current_package_version[:current_package_version.find("-")]
    else:
        log.info("unhandled version number:%s image_id=%s" % (package, image_id))

    if fix_version.has_key(package_name):
        log.debug("The version found for %s is %s" % (package_name, fix_version[package_name]))
        package_version = fix_version[package_name]
    else:
        while True:

            url = "https://mvnrepository.com/artifact/%s/%s" % (group_id, package_name)
            log.debug(url)

            resp = retry_get(url=url, verify=False)
            if resp.status_code == 403:
                log.info("Find package exceptions，status=%s" % resp.status_code)
                time.sleep(5)
            elif resp.status_code == 404:
                fix_version[package_name] = package_version
                break
            else:
                version_list = re.findall(r'class="vbtn release">(.+?)</a>', resp.text)
                if version_list:
                    for version_item in version_list:
                        if version_item.startswith(current_package_version):
                            package_version["same_version"] = version_item
                            break

                    package_version["last_version"] = version_list[0]
                    fix_version[package_name] = package_version
                    break

    return package_version


def sync_data(imageId=None, force=False):
    try:
        mongo_anchore_result = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL]
        # Get all images in local db sorted by created_at DESCENDING
        all_images = mongo_anchore_result.find({}, {"imageId": 1, "fulltag": 1, "analyzed_at": 1}, sort=[('created_at', -1)])

        # List all image tags in Anchore visible to the user
        resp_summaries = req(ANCHORE_API + "/summaries/imagetags", ANCHORE_USERNAME, ANCHORE_PASSWORD)

        if resp_summaries:
            if imageId:
                # In case of sync a specific image, filter out wanted images from Anchore results
                for resp_dict in resp_summaries:
                    if resp_dict["imageId"] == imageId:
                        resp_summaries = [resp_dict]
                        break
                else:
                    return True
            else:
                # In case of a global sync, sort Anchore results by created_at DESCENDING
                resp_summaries.sort(key=lambda x: x["analyzed_at"], reverse=True)
                # If last analysis returned by Anchore = last one in local db, stop here (we are up to date)
                if all_images.count() and  resp_summaries[0]["analyzed_at"] == all_images[0]["analyzed_at"]:
                    resp_summaries = []
            
            # Retain a list of known images in local db (triplet imageid/fulltag/analyzed_at)
            # We want all fulltag and all images for this tag to get a trend by tag
            # And an analysis can be forced and so will get a new analyzed_at
            all_images_id_tag = map(lambda x: x["imageId"]+"-"+x["fulltag"]+"-"+timestamp2str(x["analyzed_at"]), all_images)

            # Loop on Anchore results
            for image in resp_summaries:
                # If current analysis concerns a triplet not known locally, or we force sync, init a new local image object
                image_id_tag = ""+image["imageId"]+"-"+image["fulltag"]+"-"+timestamp2str(image["analyzed_at"])
                if image_id_tag not in all_images_id_tag or force == True:
                    risk = {
                        'critical': 0,
                        'high': 0,
                        'medium': 0,
                        'low': 0,
                        'negligible': 0,
                        'unknown': 0
                    }
                    affected_package_count = set()

                    image["project_name"] = image['fulltag'][
                                            image['fulltag'].rfind("/") + 1:image['fulltag'].rfind(":")]

                    image["publisher"] = ""
                    if image["analysis_status"] == "analyzed":
                        log.info("synchronizing:%s-%s" % (image["imageId"], image['fulltag']))
                        resp_vlun = req(ANCHORE_API + "/images/by_id/" + image["imageId"] + "/vuln/all",
                                        ANCHORE_USERNAME, ANCHORE_PASSWORD)
                        if resp_vlun:

                            # TODO: what does this do ?
                            dependency_list = []
                            resp_dependency = req(
                                GET_DEPENDENCY_API + "/dependency/result/?docker_url=" + image['fulltag'])

                            if resp_dependency:
                                dependency_result = base64.b64decode(resp_dependency["result"])
                                dependency_list = get_parents(dependency_result)
                                image["publisher"] = resp_dependency["publisher"]

                            # Manage vulnerabilities 1 by 1
                            for vlun_item in resp_vlun['vulnerabilities']:
                                # Add package_name to the set
                                affected_package_count.add(vlun_item['package_name'])

                                # Get package name
                                if vlun_item["package_type"] == "java":
                                    package_name = vlun_item["package_path"][
                                                   vlun_item["package_path"].rfind('/') + 1:]
                                    package_name = re.findall(r'(.+)-\d+\.', package_name)
                                    if len(package_name):
                                        package_name = package_name[0]
                                    else:
                                        package_name = re.sub(r'-\d+|\.\d+|\.jar', "", package_name)

                                else:
                                    package_name = vlun_item["package_name"]
                                vlun_item["package_name"] = package_name

                                # Increment corresponding severity
                                if vlun_item['severity'] == "Critical":
                                    risk['critical'] += 1
                                elif vlun_item['severity'] == "High":
                                    risk['high'] += 1
                                elif vlun_item['severity'] == "Medium":
                                    risk['medium'] += 1
                                elif vlun_item['severity'] == "Low":
                                    risk['low'] += 1
                                elif vlun_item['severity'] == "Negligible":
                                    risk['negligible'] += 1
                                elif vlun_item['severity'] == "Unknown":
                                    risk['unknown'] += 1

                                # TODO: what does this do ?
                                for k in dependency_list:
                                    if vlun_item["package_name"] in k["child"]:
                                        vlun_item["parents"] = k["parents"]
                                        vlun_item["group_id"] = k["group_id"]

                                # TODO: what does this do ?
                                if vlun_item["fix"] == "None":

                                    if dependency_list:  # There is a dependency list, and some projects do not use mvn, so there is no dependency list
                                        try:
                                            if vlun_item["package_type"] == "java":  # get_version only support java

                                                package_version = get_version(vlun_item["group_id"],
                                                                              vlun_item["parents"],
                                                                              image["imageId"])
                                                vlun_item["fix"] = package_version["last_version"]
                                                vlun_item["second_fix_version"] = package_version["same_version"]

                                            elif vlun_item["package_type"] == "python":
                                                pass

                                            else:
                                                log.warning(
                                                    "[%s][%s]Packet type unhandled：%s" % (
                                                        vlun_item["package"], vlun_item["package_type"],
                                                        image["imageId"]))
                                                vlun_item["fix"] = ""
                                                vlun_item["second_fix_version"] = ""
                                        except Exception, e:
                                            log.exception(
                                                "Error getting version：【%s】%s" % (vlun_item["package"], image["imageId"]))
                                            vlun_item["fix"] = ""
                                            vlun_item["second_fix_version"] = ""

                            image["affected_package_count"] = len(affected_package_count)
                            image["vulnerabilities"] = resp_vlun["vulnerabilities"]
                            image["risk"] = risk

                    elif image["analysis_status"] == "analysis_failed":
                        image["vulnerabilities"] = []
                        image["affected_package_count"] = 0
                        image["risk"] = risk
                    else:
                        log.info("【Task in scan】created_at=%s,fulltag=%s" % (
                            timestamp2str(image["created_at"]), image["fulltag"]))

                    if image["analysis_status"] == "analyzed" or image["analysis_status"] == "analysis_failed":
                        log.info("add image %s-%s" % (image["imageId"], image['fulltag']))
                        mongo_anchore_result.update_many({"imageId": image["imageId"], "fulltag": image["fulltag"], "fulltag": image["analyzed_at"]}, {"$set": image}, upsert=True)


        return True
    except:
        log.exception("Error synchronizing data")
    return False


if __name__ == '__main__':
    sync_data("9f55d67f883db748711d661a477f714ce330eccf303710c3ddc0fdbca1e39e1a")
    # get_version("spring-boot-starter-validation:1.5.9.RELEASE")
