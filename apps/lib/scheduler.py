# !/usr/bin/env python
# -*- coding: utf-8 -*-
from common import sync_data
from apps import apscheduler, log


class Scheduler(object):

    def __init__(self, scheduler_name="sync_anchore_data"):
        self.scheduler_name = scheduler_name
        self.final_result = {
            "status": "error",
            "content": "Error",
            "data": {}
        }

    def refresh(self):
        if sync_data():
            self.final_result["status"] = "success"
            self.final_result["content"] = "Synchronized data successfully"

        else:
            self.final_result["status"] = "error"
            self.final_result["content"] = "Sync data failed"
        return self.final_result

    def add(self, job_time=None, job_unit=None):
        try:
            job_time = float(job_time)

            # job_unit = "hours" if job_unit == "hours" else "minutes"

            job = apscheduler.add_job(func="apps.lib.common:sync_data", id=self.scheduler_name,
                                      trigger="interval",
                                      replace_existing=True, **{job_unit: job_time})
        except:
            log.exception("Error adding scheduled task")
            self.final_result["status"] = "error"
            self.final_result["content"] = "Error adding scheduled task"

        self.final_result["status"] = "success"
        self.final_result["content"] = "Added scheduled task successfully"
        self.final_result["redirect"] = "/images_sync"

        return self.final_result

    def remove(self):
        try:
            apscheduler.delete_job(id=self.scheduler_name)
            self.final_result["status"] = "success"
            self.final_result["content"] = "Clear scheduled tasks"
        except:
            log.exception("Error clearing scheduled tasks")
            self.final_result["status"] = "error"
            self.final_result["content"] = "Error clearing scheduled tasks"
        return self.final_result
    def get(self):
        aps = apscheduler.get_job(id=self.scheduler_name)
        if aps:
            if aps.next_run_time:
                next_run_time = aps.next_run_time.strftime(
                    "%Y-%m-%d %H:%M:%S")
                self.final_result = {
                    "status": "success",
                    "content": "Get scheduled task success",
                    "data": {
                        "id": self.scheduler_name,
                        "next_run_time": next_run_time
                    }
                }
        else:
            self.final_result = {
                "status": "success",
                "content": "Get scheduled task success",
                "data": {"id": self.scheduler_name, "next_run_time": ""}
            }
        return self.final_result
