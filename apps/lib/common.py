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
        "imageId": [],
        "created_at": [],
        "critical": [],
        "high": [],
        "low": [],
        "medium": [],
        "negligible": [],
        "unknown": []

    }
    try:
        images = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL].find({"fulltag": fulltag}).sort("created_at", -1).limit(n)

        if images.count():
            for i in images:
                final_result["created_at"].insert(0, timestamp2str(i["created_at"]) + "\n(" + i["imageId"] + ")")
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
# Return last image analysis
##
def get_last_image_analysis(fulltag=""):
    #log.debug("get_last_image_analysis(%s)" % fulltag)
    images_details = {}

    mongo_anchore_result = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL]
    # Find last image analysis
    lastImageAnalysis = mongo_anchore_result.find_one(filter={"fulltag": fulltag}, sort=[("created_at", -1)])

    if lastImageAnalysis:
        #log.debug("imageId: %s" % lastImageAnalysis["imageId"])

        # Construct DTO
        images_details["imageId"] = lastImageAnalysis["imageId"]
        images_details["fulltag"] = lastImageAnalysis["fulltag"]
        images_details["project_name"] = lastImageAnalysis["project_name"]
        images_details["total_package"] = {}
        images_details["vulnerabilities"] = lastImageAnalysis["vulnerabilities"]

        # Aggregate packages of LAST image analysis
        total_package_sum = mongo_anchore_result.aggregate([
            {'$match': {'_id': lastImageAnalysis["_id"]}},
            {"$unwind": "$vulnerabilities"},
            {"$group": {"_id": "$vulnerabilities.package_name", "sum": {"$sum": 1}}},
            {"$sort": {"sum": -1}},
            {"$limit": 10}
        ])
        for i in total_package_sum:
            images_details["total_package"][i["_id"]] = i["sum"]

        images_details["total_risk"] = lastImageAnalysis["risk"]
    return images_details

##
# Return collection of images grouped by fulltag and giving last image analysis summary and evaluation status
##
def get_images():
    final_result = []
    # Get all analysis
    mongo_anchore_result = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL]
    images = mongo_anchore_result.find()
    if images.count():

        # Sort by analyzed_at, then Group by fulltag
        images_analysis = mongo_anchore_result.aggregate([
            # Explode 'evaluations' (image can have 0 evaluations)
            {
                "$unwind" : {
                    "path" : "$evaluations",
                    "preserveNullAndEmptyArrays" : True
                }
            }, 
            # Convert evaluations.last_evaluation from string to seconds from epoch
            {
                "$addFields" : {
                    "last_evaluation" : {
                        "$divide" : [
                            {
                                "$convert" : {
                                    "input" : {
                                        "$toDate" :
                                            "$evaluations.last_evaluation"
                                    },
                                    "to" : "double"
                                }
                            },
                            1000.0
                        ]
                    }
                }
            },
            # Sort by created_at DESC then last last_evaluation DESC
            {
                "$sort" : {
                    "created_at" : -1,
                    "last_evaluation" : -1
                }
            },
            # Group by fulltag, get 1st tuple
            {
                "$group" : {
                    "_id" : "$fulltag",
                    "created_at" : {
                        "$first" : "$created_at"
                    },
                    "last_evaluation" : {
                        "$first" : "$last_evaluation"
                    },
                    "risk" : {
                        "$first" : "$risk"
                    },
                    "affected_package_count" : {
                        "$first" : "$affected_package_count"
                    },
                    "eval_status" : {
                        "$first" : "$evaluations.status"
                    },
                    "analysis_status" : {
                        "$first" : "$analysis_status"
                    }
                }
            }
        ])

        # Construct DTOs
        for i in images_analysis:

            #log.debug("Image %s" % i["_id"])

            project_result = {}
            try:

                project_result["affected_package_count"] = i.get("affected_package_count", "")
                project_result["fulltag"] = i["_id"]
                project_result["created_at"] = timestamp2str(i["created_at"])
                project_result["last_evaluation"] = timestamp2str(i["last_evaluation"])
                project_result["eval_status"] = i["eval_status"]
                project_result["analysis_status"] = i["analysis_status"]


                project_result["critical"] = i["risk"]["critical"]
                project_result["high"] = i["risk"]["high"]
                project_result["medium"] = i["risk"]["medium"]
                project_result["low"] = i["risk"]["low"]
                project_result["negligible"] = i["risk"]["negligible"]
                project_result["unknown"] = i["risk"]["unknown"]
                final_result.append(project_result)

            except:
                log.exception(i)
    return final_result

##
# Retrieve new analysis and stores them in Mongo
# return: 0 if ok, -1 if fails, 1 if some non fatal errors
##
def sync_data(force=False):
    try:
        syncSuccess = True

        # Get all images in local db and map them to a list
        mongo_anchore_result = mongo.conn[MONGO_DB_NAME][MONGO_SCAN_RESULT_COLL]
        all_local_images = mongo_anchore_result.find({}, {"imageId": 1, "fulltag": 1})

        # List all pairs (imageId, fulltag) in Anchore visible to the user
        anchore_summaries = req(ANCHORE_API + "/summaries/imagetags", ANCHORE_USERNAME, ANCHORE_PASSWORD)

        # Get image to delete locally
        list_local_images = map(lambda x:  {"imageId": x["imageId"], "fulltag": x["fulltag"]}, all_local_images)
        list_anchore_summaries = map(lambda x:  {"imageId": x["imageId"], "fulltag": x["fulltag"]}, anchore_summaries)
        toDelete = diff = [item for item in list_local_images if item not in list_anchore_summaries]

        ####################################################################################
        # Update or Insert
        log.info("Sync: %i images to upsert" % len(anchore_summaries))
        for image in anchore_summaries:

            # # Remove image from all_local_images
            # image_to_remove = {"imageId":image["imageId"], "fulltag": image['fulltag']}
            # local_images_not_in_anchore = [x for x in local_images_not_in_anchore if not all(x.get(k)==v for k,v in image_to_remove.items() )]

            try:
                log.info("Sync: Upsert: %s-%s" % (image["imageId"], image['fulltag']))
                # Init an empty risk
                risk = {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'negligible': 0,
                    'unknown': 0
                }
                image["risk"] = risk
                image["vulnerabilities"] = []
                image["affected_package_count"] = 0
                image["evaluations"] = []
                affected_package_count = set()
                # Extract project name
                image["project_name"] = image['fulltag'][
                                        image['fulltag'].rfind("/") + 1:image['fulltag'].rfind(":")]

                # If current analysis is failed, drop last analysis date (if a previous date was set, Anchore let it)
                if image["analysis_status"] == "analysis_failed":
                    image["analyzed_at"] = None

                # New triplet is in status "analyzed" ? => Get vulns and evaluations
                if image["analysis_status"] == "analyzed":
                    ###################
                    # Get all vulns
                    ###################
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

                        image["vulnerabilities"] = resp_vlun["vulnerabilities"]
                        image["affected_package_count"] = len(affected_package_count)                        
                        image["risk"] = risk

                    ###################
                    # Get all evaluations (evaluations can appear even without new analysis)
                    ###################
                    evaluations = req(ANCHORE_API + "/images/by_id/" + image["imageId"] + "/check?tag="+image["fulltag"],
                                    ANCHORE_USERNAME, ANCHORE_PASSWORD)
                    if evaluations:                        
                        evaluation_list = evaluations[0][image["imageDigest"]][image["fulltag"]]
                        #log.debug(evaluation_list)
                        image["evaluations"] = evaluation_list

                ###################
                # Persist if analysis is OK or KO, not pending
                ###################
                if image["analysis_status"] == "analyzed" or image["analysis_status"] == "analysis_failed":
                    # Insert or update, use pair (imageId, fulltag) as key
                    mongo_anchore_result.update_one({"imageId": image["imageId"], "fulltag": image["fulltag"]}, {"$set": image}, upsert=True)
                    log.info("Sync: Upserted image: %s-%s" % (image["imageId"], image['fulltag']))
                else:
                    log.info("Sync: mage currently in analysis: %s-%s" % (image["imageId"], image['fulltag']))

            except Exception as e:
                # Log error on image but continue on others
                log.exception("Sync: Error upserting %s" % image["imageId"])
                syncSuccess = False
        # end loop
        ####################################################################################

        ####################################################################################
        # Delete all records in local_images_not_in_anchore
        log.info("Sync: %i images to delete" % len(toDelete))
        for image_to_delete in toDelete:
            try:
                log.info("Sync: Delete image: %s" % image_to_delete)
                mongo_anchore_result.delete_many({"imageId": image_to_delete["imageId"], "fulltag": image_to_delete["fulltag"]})
                log.info("Sync: Deleted image: %s" % image_to_delete)
            except Exception as e:
                log.exception("Sync: Error deleting %s" % image_to_delete)
                syncSuccess = False
        # end loop
        ####################################################################################

        if syncSuccess:
            return 0
        else:
            return 1
    except:
        log.exception("Error synchronizing data")
        return -1
