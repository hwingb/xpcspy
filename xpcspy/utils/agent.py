from os import path
from collections import OrderedDict

import frida

from plist17lib import _BinaryPlist17Parser
from io import BytesIO
import json
import base64

from ..lib.types import Event
import datetime

class Agent:
    def __init__(self, filter, should_parse, session, reactor, print_timestamp=False):
        """
        Initialize the Frida agent
        """
        self._pending_events = OrderedDict() # A map of stacks, each stack holding events for that particular timestamp
        self._filter = filter
        self._should_parse = should_parse
        self._print_timestamp = print_timestamp
        self._script_path = path.join(path.abspath(path.dirname(__file__)), '../../_agent.js')
        with open(self._script_path) as src_f:
            script_src = src_f.read()
        self._script = session.create_script(script_src)
        self._reactor = reactor
        self._agent = None
        

    def start_hooking(self, ui):
        def on_message(message, data):
            self._reactor.schedule(lambda: self._on_message(message, data, ui))

        self._script.on('message', on_message)
        self._script.load()
        ui._update_status("Installing hooks...")
        self._agent = self._script.exports
        self._agent.install_hooks(self._filter, self._should_parse)

    def _on_message(self, message, data, ui):
        if message['type'] == 'error':
            ui._log("error", message['stack'])
        mtype = message['payload']['type']

        if mtype == 'agent:hooks_installed':
            ui._update_status("Hooks installed, intercepting messages...")
            ui._resume()
        elif mtype == 'agent:trace:symbol':
            symbol = message['payload']['message']['symbol']
            timestamp = message['payload']['message']['timestamp']
            if timestamp in self._pending_events:
                self._pending_events[timestamp].append(Event(symbol)) 
                #print(f"Update {timestamp}")
            else:
                self._pending_events.update({ timestamp: [Event(symbol)] })
                #print(f"Add {timestamp}")
        elif mtype == 'agent:trace:data':
            timestamp = message['payload']['message']['timestamp']
            data = message['payload']['message']['data']
            data_message : str = data["message"]
            # Special case for bplist17, as it is parsed on the python side
            if isinstance(data_message, str) and data_message.startswith('bplist17:'):
                data_message_parts = data_message.split(':')
                if len(data_message_parts) > 1:
                    data_message_b64 = data_message_parts[1]
                    base64_bytes = data_message_b64.encode('ascii')
                    plist_bytes = base64.b64decode(base64_bytes)
                    data["message"] = self._parseBPlist17(plist_bytes=plist_bytes)

            self._pending_events[timestamp][-1].data = data
        
        else:
            ui._print(f"Unhandled message {message}")

        self.flush_pending_events()

    def flush_pending_events(self):
        """Flush pending events that are ready, i.e. have received both its symbol and data"""
        for ts, events_stack in list(self._pending_events.items()):
            while len(events_stack) > 0:
                last_event = events_stack[-1]  # Peek
                if last_event.data == None:
                    return
                #print(f"Pop {ts}")
                print('\n' + '-' * 60)
                if (self._print_timestamp):
                    date_time = datetime.datetime.fromtimestamp((ts/1000))
                    print(f"{date_time}")
                print(f"{last_event.symbol}\n{last_event.data['conn']}\n{last_event.data['message']}")
                print('-' * 60 + '\n')
                events_stack.pop()
            del self._pending_events[ts]

    def _parseBPlist17(self, plist_bytes: bytes): 
        fp = BytesIO(plist_bytes)
        parser1 = _BinaryPlist17Parser(dict_type=dict)
        fp.seek(0)
        result = parser1.parse(fp, with_type_info=False)
        bplist_json = json.dumps(result, indent=2)
        return  bplist_json