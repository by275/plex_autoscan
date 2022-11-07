import copy
import datetime
import queue
import threading


class PriorityLock:
    def __init__(self):
        self._is_available = True
        self._mutex = threading.Lock()
        self._waiter_queue = queue.PriorityQueue()

    def acquire(self, priority=0):
        with self._mutex:
            # First, just check the lock.
            if self._is_available:
                self._is_available = False
                return True
            event = threading.Event()
            self._waiter_queue.put((priority, datetime.datetime.now(), event))
        event.wait()
        # When the event is triggered, we have the lock.
        return True

    def release(self):
        with self._mutex:
            # Notify the next thread in line, if any.
            try:
                _, _, event = self._waiter_queue.get_nowait()
            except queue.Empty:
                self._is_available = True
            else:
                event.set()


class Thread:
    def __init__(self):
        self.threads = []

    def start(self, target, **kwargs):
        track = kwargs.pop("track", False)
        thread = threading.Thread(target=target, **kwargs)
        thread.name = thread.name.split()[0]  # not to include target name
        thread.daemon = True
        thread.start()
        if track:
            self.threads.append(thread)
        return thread

    def join(self):
        for thread in copy.copy(self.threads):
            thread.join()
            self.threads.remove(thread)

    def kill(self):
        for thread in copy.copy(self.threads):
            thread.kill()
            self.threads.remove(thread)
