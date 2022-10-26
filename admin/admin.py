import cmd2
from config import Config
from getpass import getpass
import json
import logging
from platform import system
import requests


def noargs(command):
    def wrapper(self, args):
        if args:
            self.perror('This command takes no arguments')
        else:
            command(self)
    return wrapper


def RequestError(Exception):
    pass


class AdminShell(cmd2.Cmd):
    def __init__(self, completekey='tab', stdin=None, stdout=None, commanderServer="", logLevel=4):
        super().__init__(completekey, stdin, stdout)
        self.log = self.logInit(logLevel)
        self.commanderServer = commanderServer
        self.serverCert = "commander.crt"
        self.username, self.authToken = self.login(0)
        self.headers = {"Content-Type": "application/json",
                        "Username": self.username,
                        "Auth-Token": self.authToken}
        # TODO: cache hosts and groups locally for tab completion
        # set prompt experience
        self.hostgroup = []
        self.intro = f"Welcome to the {Config.APP_NAME} admin shell. Type help or ? to list commands."
        self.prompt = f"{self.username}@{Config.APP_NAME.lower()}> "

    # ----- Helper Functions -----
    def request(self, method, directory, body=None, headers=None, files=None):
        """ HTTPS request to the server using client and server verification """
        if headers is None:
            headers = self.headers
        if body is None:
            body = {}  # set here to prevent mutating default arg
        if files is None:
            files = {}
        if method == "GET":
            response = requests.get(f"https://{self.commanderServer}{directory}",
                                    headers=headers,
                                    verify=self.serverCert,
                                    data=body)
        elif method == "POST":
            response = requests.post(f"https://{self.commanderServer}{directory}",
                                     headers=headers,
                                     verify=self.serverCert,
                                     data=body,
                                     files=files)
        elif method == "PUT":
            response = requests.put(f"https://{self.commanderServer}{directory}",
                                    headers=headers,
                                    verify=self.serverCert,
                                    data=body,
                                    files=files)
        elif method == "DELETE":
            response = requests.delete(f"https://{self.commanderServer}{directory}",
                                       headers=headers,
                                       verify=self.serverCert,
                                       data=body,
                                       files=files)
        elif method == "PATCH":
            response = requests.patch(f"https://{self.commanderServer}{directory}",
                                      headers=headers,
                                      verify=self.serverCert,
                                      data=body,
                                      files=files)
        if "error" in response.json():
            self.perror(f"Error submitting request: {response.json()['error']}\n")
            self.perror("Please try again.")
            raise RequestError()
        return response

    def logInit(self, logLevel):
        """ Configure log level (1-5) and OS-dependent log file location """
        # set log level
        level = [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL][5-logLevel]
        logging.basicConfig(level=level)
        log = logging.getLogger("CommanderAgent")
        formatter = logging.Formatter(fmt="%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s",
                                      datefmt="%Y-%m-%d %H:%M:%S")
        os = system()
        if os == "Linux" or os == "Darwin":
            handler = logging.TimedRotatingFileHandler(filename="/var/log/commander.log",
                                                   encoding="utf-8",
                                                   when="D",  # Daily
                                                   backupCount=7)
        elif os == "Windows":
            handler = logging.TimedRotatingFileHandler(filename="commander.log",
                                                   encoding="utf-8",
                                                   when="D",  # Daily
                                                   backupCount=7)
        handler.setFormatter(formatter)
        log.addHandler(handler)
        return log

    def login(self, tries):
        """ Login to the server and get new authentication token """
        if tries == 3:
            self.perror("Too many failed login attempts. Exiting...")
            exit(1)
        username = input("Username: ")
        password = getpass("Password: ")
        try:
            response = self.request("GET", "/admin/login",
                                    headers={"Content-Type": "application/json"},
                                    body={"Username": username, "Password": password})
            creds = response.json()
        except RequestError:
            creds = self.login(tries+1)
        return creds["username"], creds["authToken"]
    
    # ----- State Management Commands -----
    
    def do_set(self, hosts):
        """
        Select the specified host(s) for use with future commands:\n\t\
            set <host>|<hostgroup> ... <host>|<hostgroup>
        """
        for arg in hosts.arg_list:
            if arg == "all":
                self.hostgroup = ["all"]
                return
            self.hostgroup.append(arg)
    
    def do_unset(self, hosts):
        """
        Unselect all hosts or the specified host(s):\n\t\
            unset [<host>|<hostgroup> ... <host>|<hostgroup>]
        """
        if not hosts:
            self.hostgroup = []
            return
        for host in hosts.arg_list:
            if host in self.hostgroup:
                try:
                    self.hostgroup.remove(host)
                except ValueError:
                    print(f"Warning: {host} not found in hostgroup. Skipping...")
                 
    @noargs   
    def do_hosts(self, args):
        """ List selected hosts:\n\thosts """
        for host in self.hostgroup:
            print(host)

    # ----- Account Management Commands -----
    def do_passwd(self, username=""):
        """
        Reset the admin password for the given user:
            passwd [<username>]
        """
        if not username:
            username = self.username
        print(f"Resetting password for '{username}'")
        currentPassword = getpass("Current password: ")
        newPassword = getpass("New password: ")
        confirm = getpass("Confirm new password: ")
        while newPassword != confirm:
            print("Passwords do not match, please try again.")
            newPassword = getpass("New password: ")
            confirm = getpass("Confirm new password: ")
        response = self.request("PATCH", "/admin/login",
                                body={"username": self.username,
                                      "current": currentPassword,
                                      "new": newPassword})
        if "error" in response.json():
            print(f"Error submitting request: {response.json()['error']}")
            print("Please try again.")
        else:
            print(f"Successfully changed password for '{self.username}'")
            
    def do_useradd(self, username):
        """
        Add a new admin user:\n\t\
            useradd <username>
        """
        pass
    
    def do_userdel(self, username):
        """
        Delete an admin user:\n\t\
            userdel <username>
        """
        pass

    # ----- Agent Install Commands -----
    @noargs
    def do_regkey(self, args):
        """
        Reset and fetch registration key to register new clients:\n\t\
            regkey
        """
        response = self.request("GET", "/admin/registration-key")
        if "error" in response.json():
            print(f"Error submitting request: {response.json()['error']}")
            print("Please try again.")
        else:
            print(f"Registration Key: {response.json()['registration-key']}")

    @noargs
    def do_newregkey(self, args):
        """
        Reset and fetch registration key to register new clients:\n\t\
            newregkey
        """
        response = self.request("PUT", "/admin/registration-key")
        if "error" in response.json():
            print(f"Error submitting request: {response.json()['error']}")
            print("Please try again.")
        else:
            print(f"Registration Key: {response.json()['registration-key']}")
            
    def do_installer(self, version="latest"):
        """
        List agent installers or fetch one (default is latest version):\n\t\
            installer [list|<version>]
        """
        pass

    # ----- Job Management Commands -----
    def do_execute(self, filename):
        """
        Send a file from the library to the selected host(s) and execute it\n\t\
            execute <filename>
        """
        print(f"Assigning {filename} to {', ' .join(self.hostgroup)}...")
        print("Failed hostnames will be sent to stderr and successes to stdout.")
        for hostname in self.hostgroup:
            try:
                response = self.request("POST", "/agent/jobs",
                                        body={"hostname": hostname,
                                              "filename": filename})
            except RequestError:
                self.perror(hostname)
            else:
                self.poutput(hostname)
            
    def do_search(self, args):
        """
        Search for jobs:\n\t\
            search hosts|groups|library|results <query>
        """
        pass
    
    def do_history(self, number):
        """
        Fetch the entire job history for the selected hosts, or specify the number of jobs to return:\n\t\
            history [<number>]
        """
        pass
    
    @noargs
    def do_results(self, args):
        """
        Fetch most recent job on all selected hosts:\n\t\
            results
        """
        pass
    
    def do_job(self, jobID):
        """
        Fetch the details of the specified job:\n\t\
            job <jobID>
        """
        pass

    @noargs
    def do_library(self, args):
        """
        Receive the execution library from the server and format output:\n\t\
            library
        """
        response = self.request("GET", "/admin/library")
        library = response.json()["library"]
        for executable in library:
            print(f"<-- {executable['fileName']} -->")
            print(f"Submitted by: {executable['user']} on {executable['timeSubmitted']}")
            print(f"Description: {executable['description']}")
            
    def do_bundle(self, filename):
        """
        Bundle an executable into the expect jobfile format:\n\t\
            bundle <filename>
        """
        pass

    def do_addjob(self, filePath, description=""):
        """
        Upload a new executable package to the library:\n\t\
            addjob <path> [description]
        """
        if "/" in filePath:
            filename = filePath[filePath.rindex("/"):]
        elif "\\" in filePath:
            filename = filePath[filePath.rindex("\\"):]
        else:
            filename = filePath
        try:
            with open(filePath, "r") as executable:
                response = self.request("POST", "/admin/library",
                                        files={"executable": executable},
                                        body={"filename": filename,
                                              "description": description})
                if "error" in response.json():
                    print(f"Error submitting request: {response.json()['error']}")
                    print("Please try again.")
                else:
                    print(f"Successfully added {filename} to the Commander library.")
        except FileNotFoundError:
            print("File not found, please check file path and try again.")

    def do_rmjob(self, filename):
        """
        Delete an executable from the library:\n\t\
            rmjob <filename>
        """
        response = self.request("DELETE", "/admin/library",
                                body={"filename": filename})
        if "error" in response.json():
            print(f"Error submitting request: {response.json()['error']}")
            print("Please try again.")
        else:
            print(f"Successfully deleted {filename} from the library.")

    def do_modjob(self, filename="", filePath="", description=""):
        """
        Update the description or file version of an job in the library:\n\t\
            modjob <filename> <filepath>|<description>
        """
        # TODO: fix argument parsing
        try:
            with open(filePath, "r") as executable:
                response = self.request("PATCH", "/admin/library",
                                        files={"executable": executable},
                                        body={"filename": filename})
                if "error" in response.json():
                    print(f"Error submitting request: {response.json()['error']}")
                    print("Please try again.")
                else:
                    print(f"Successfully updated {filename} in the Commander library.")
        except FileNotFoundError:
            print("File not found, please check file path and try again.")
            
    # ----- Record and Playback -----
    def do_record(self, outfile):
        """
        Save future commands to filename:\n\t\
            record <outfile>.cmdr
        """
        self.file = open(outfile, 'w')

    def do_playback(self, infile):
        """
        Playback commands from a file:\n\t\
            playback <infile>.cmdr
        """
        self.close()
        with open(infile) as f:
            self.cmdqueue.extend(f.read().splitlines())

    def precmd(self, line):
        line = line.lower()
        if self.file and 'playback' not in line:
            print(line, file=self.file)
        return line
    
    def close(self):
        if self.file:
            self.file.close()
            self.file = None