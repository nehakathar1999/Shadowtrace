from apscheduler.schedulers.background import BackgroundScheduler
from api.routes import save_report

scheduler = BackgroundScheduler()

def threat_data_sync():
    # placeholder; implement periodic feed ingestion from your external CVE sources
    print("[threat_backend] scheduled threat sync executed")


def start_scheduler():
    scheduler.add_job(threat_data_sync, "interval", minutes=60)
    scheduler.start()


def stop_scheduler():
    scheduler.shutdown(wait=False)

