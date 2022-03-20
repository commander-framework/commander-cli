import json
from server.routes import agentCheckin
from utils import timestampToDatetime


class MockServer:
    def __init__(self, agentID):
        self.lastMessage = None
        self.agentID = agentID
        self.isMockServer = True
    def send(self, msg):
        self.lastMessage = msg
    def receive(self):
        if not self.lastMessage:
            # send given Agent ID in valid json format
            return json.dumps({"Agent-ID": self.agentID})
        else:
            # response to a job being assigned to the endpoint
            return "ack"
    def close(self, *args, **kwargs):
        return


def testAssignJob(client, sample_Job, sample_Library, sample_Agent, sample_valid_Session, sample_User):
    # prepare mongomock with relevant sample documents
    user = sample_User
    user["sessions"].append(sample_valid_Session)
    user.save()
    agent = sample_Agent
    agent.save()
    library = sample_Library
    library["jobs"].append(sample_Job)
    library.save()
    # send job to api
    response = client.post("/agent/jobs",
                           headers={"Content-Type": "application/json",
                                    "Auth-Token": sample_valid_Session["authToken"],
                                    "Username": sample_valid_Session["username"]},
                           data=json.dumps({"agentID": sample_Agent["agentID"],
                                 "filename": sample_Job["filename"],
                                 "argv": []}))
    assert response.status_code == 200
    assert response.json["success"] == "job successfully submitted -- waiting for agent to check in"
    # check in and make sure job is in agent's queue now
    agentCheckin.__wrapped__(MockServer(agent["agentID"]))
    # make sure all job fields were included from the sample job
    agent.reload()
    job = agent.jobsRunning[0]
    assert job["executor"] == sample_Job["executor"]
    assert job["filename"] == sample_Job["filename"]
    assert job["description"] == sample_Job["description"]
    assert job["os"] == sample_Job["os"]
    assert job["user"] == sample_Job["user"]
    # make sure timeDispatched was created
    createdTimestamp = job["timeCreated"]
    createdTime = timestampToDatetime(createdTimestamp)
    dispatchTimestamp = job["timeDispatched"]
    dispatchTime = timestampToDatetime(dispatchTimestamp)
    assert dispatchTime >= createdTime


def testExpiredSessionAssignJob(client, sample_Job, sample_Library, sample_Agent, sample_expired_Session, sample_User):
    # prepare mongomock with relevant sample documents
    user = sample_User
    user["sessions"].append(sample_expired_Session)
    user.save()
    agent = sample_Agent
    agent.save()
    library = sample_Library
    library["jobs"].append(sample_Job)
    library.save()
    # send job to api
    response = client.post("/agent/jobs",
                           headers={"Content-Type": "application/json",
                                    "Auth-Token": sample_expired_Session["authToken"],
                                    "Username": sample_expired_Session["username"]},
                           data=json.dumps({"agentID": sample_Agent["agentID"],
                                 "filename": sample_Job["filename"],
                                 "argv": []}))
    assert response.status_code == 401
    assert response.json["error"] == "invalid auth token or token expired"


def testNoLibraryAssignJob(client, sample_Job, sample_Agent, sample_valid_Session, sample_User):
    # prepare mongomock with relevant sample documents
    user = sample_User
    user["sessions"].append(sample_valid_Session)
    user.save()
    agent = sample_Agent
    agent.save()
    # intentionally not creating a library document in the database
    # send job to api
    response = client.post("/agent/jobs",
                           headers={"Content-Type": "application/json",
                                    "Auth-Token": sample_valid_Session["authToken"],
                                    "Username": sample_valid_Session["username"]},
                           data=json.dumps({"agentID": sample_Agent["agentID"],
                                 "filename": sample_Job["filename"],
                                 "argv": []}))
    assert response.status_code == 400
    assert response.json["error"] == "there are no jobs in the library yet"


def testJobMissingAssignJob(client, sample_Job, sample_Library, sample_Agent, sample_valid_Session, sample_User):
    # prepare mongomock with relevant sample documents
    user = sample_User
    user["sessions"].append(sample_valid_Session)
    user.save()
    agent = sample_Agent
    agent.save()
    library = sample_Library
    # intentionally not adding sample_Job to the library
    library.save()
    # send job to api
    response = client.post("/agent/jobs",
                           headers={"Content-Type": "application/json",
                                    "Auth-Token": sample_valid_Session["authToken"],
                                    "Username": sample_valid_Session["username"]},
                           data=json.dumps({"agentID": sample_Agent["agentID"],
                                 "filename": sample_Job["filename"],
                                 "argv": []}))
    assert response.status_code == 400
    assert response.json["error"] == "the library contains no executable with the given filename"


def testBadAgentIDAssignJob(client, sample_Job, sample_Library, sample_Agent, sample_valid_Session, sample_User):
    # prepare mongomock with relevant sample documents
    user = sample_User
    user["sessions"].append(sample_valid_Session)
    user.save()
    # intentionally not adding agent document to the library
    library = sample_Library
    library["jobs"].append(sample_Job)
    library.save()
    # send job to api
    response = client.post("/agent/jobs",
                           headers={"Content-Type": "application/json",
                                    "Auth-Token": sample_valid_Session["authToken"],
                                    "Username": sample_valid_Session["username"]},
                           data=json.dumps({"agentID": sample_Agent["agentID"],
                                 "filename": sample_Job["filename"],
                                 "argv": []}))
    assert response.status_code == 400
    assert response.json["error"] == "no hosts found matching the agentID in the request"


def testMissingFieldsAssignJob(client, sample_Job, sample_Library, sample_Agent, sample_valid_Session, sample_User):
    # prepare mongomock with relevant sample documents
    user = sample_User
    user["sessions"].append(sample_valid_Session)
    user.save()
    agent = sample_Agent
    agent.save()
    library = sample_Library
    library["jobs"].append(sample_Job)
    library.save()
    # send job to api
    response = client.post("/agent/jobs",
                           headers={"Content-Type": "application/json"},
                           data=json.dumps({}))
    assert response.status_code == 400
    assert response.json["error"] == "request is missing the following parameters: headers=['Auth-Token', 'Username'], data=['agentID', 'filename', 'argv']"