from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()


def threat_data_sync():
    print("[threat_backend] scheduled threat sync executed")


def start_scheduler():
    if not scheduler.running:
        scheduler.add_job(threat_data_sync, "interval", minutes=60, id="threat_sync", replace_existing=True)
        scheduler.start()


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
