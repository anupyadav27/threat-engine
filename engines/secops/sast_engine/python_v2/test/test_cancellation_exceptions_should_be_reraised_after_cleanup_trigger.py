from asyncio import CancelledError

class SomeContextManager:
    def cleanup(self):
        pass

with SomeContextManager() as cm:
    try:
        pass
    finally:
        cm.cleanup()
        raise CancelledError()
