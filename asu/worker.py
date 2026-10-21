"""Single, non-threaded global RQ worker. Intentionally no asu.config import."""

import os
import redis
from rq import Worker, Queue


def main():
    # The unpickled job function is asu.jobs.run with plain JSON arguments.
    # Importing asu.main/build/config here would bind one cohort globally.
    connection = redis.Redis.from_url(os.environ["REDIS_URL"])
    worker = Worker([Queue(connection=connection)], connection=connection)
    worker.work()


if __name__ == "__main__":
    main()
