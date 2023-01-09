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
                "analysis_status": {"$first": "$analysis_status"}
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
                final_result.append(project_result)

            except:
                # TODO : do we sync by imageid or fulltag ?
                executor.submit(sync_data, imageId=i["imageId"], force=True)
                # sync_data(imageId=i["imageId"], force=True)
                log.exception(i)
    return final_result

##
# Retrieve new analysis and stores them in Mongo
# return: 0 if ok, -1 if fails, 1 if some non fatal errors
##
def sync_data(imageId=None, force=False):
    try:
        syncSuccess = True

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
                    return 0

            # Retain a list of known images in local db (triplet imageid/fulltag/analyzed_at)
            # We want all fulltag and all images for this tag to get a trend by tag
            # And an analysis can be forced and so will get a new analyzed_at
            all_images_id_tag = map(lambda x: x["imageId"]+"-"+x["fulltag"]+"-"+timestamp2str(x["analyzed_at"]), all_images)

            # Loop on Anchore results
            for image in resp_summaries:
                try:
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

                        if image["analysis_status"] == "analyzed":
                            log.info("synchronizing:%s-%s" % (image["imageId"], image['fulltag']))
                            resp_vlun = req(ANCHORE_API + "/images/by_id/" + image["imageId"] + "/vuln/all",
                                            ANCHORE_USERNAME, ANCHORE_PASSWORD)
                            if resp_vlun:

                                # Manage vulnerabilities 1 by 1
                                for vlun_item in resp_vlun['vulnerabilities']:
                                    # Add package_name to the set
                                    affected_package_count.add(vlun_item['package_name'])

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
                        # TODO: does Upsert makes sense ? Cause with triplets, we add every analysis now
                        mongo_anchore_result.update_many({"imageId": image["imageId"], "fulltag": image["fulltag"], "analyzed_at": image["analyzed_at"]}, {"$set": image}, upsert=True)

                except Exception as e:
                    # Log error on image but continue on others
                    log.exception("Error synchronizing %s" % image["imageId"])
                    syncSuccess = False

        if syncSuccess:
            return 0
        else:
            return 1
    except:
        log.exception("Error synchronizing data")
        return -1


if __name__ == '__main__':
    sync_data("9f55d67f883db748711d661a477f714ce330eccf303710c3ddc0fdbca1e39e1a")
    # get_version("spring-boot-starter-validation:1.5.9.RELEASE")
