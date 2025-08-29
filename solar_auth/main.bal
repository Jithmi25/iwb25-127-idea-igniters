import ballerina/crypto;
import ballerina/http;
import ballerina/jwt;
import ballerina/time;
import ballerina/uuid;
import ballerinax/mongodb;

// ===================== MongoDB Setup =====================
configurable string mongoUri = ?;

mongodb:Client mongoDb = check new ({
    connection: mongoUri
});

// ===================== JWT Config =====================
configurable string jwtIssuer = ?;
configurable string jwtAudience = ?;
configurable string jwtSecret = ?;

// ===================== HTTP Listeners =====================
listener http:Listener authListener = new (9090);
listener http:Listener passwordListener = new (9095);

// ===================== Helper functions =====================
function jsonMsg(string m) returns http:Response {
    http:Response r = new;
    r.setPayload({message: m});
    return r;
}

function createErrorResponse(string message) returns http:Response {
    http:Response r = new;
    r.statusCode = 400;
    r.setPayload({message: message});
    return r;
}

// ===================== Data Models =====================
type User record {|
    string id;
    string username;
    string password;
    string salt;
    string email;
    string? resetToken;
    int? resetExpires;
|};

type UserInput record {|
    string username;
    string password;
    string email?;
|};

type LoginInput record {|
    string username;
    string password;
|};

type ResetRequest record {|
    string username;
    string email;
|};

type ResetInput record {|
    string token;
    string newPassword;
|};

// Solar Pools 
type SolarPool record {|
    string? id;
    string name;
    string location;
    int members;
    string capacity;
    string generated;
    string investment;
    string status; // active / fundraising
    int progress;
    string image;
    string? createdAt;
|};

// Agri-Solar Projects
type AgriSolarProject record {|
    string? id;
    string name;
    string farmer;
    string location;
    string cropType;
    string landSize;
    string solarCapacity;
    string monthlyIncome;
    string image;
    string? createdAt;
|};

// Investments / Memberships 
type Investment record {|
    string? id;
    string userId; // reference to User.id
    string? poolId; // reference to SolarPool.id
    string? projectId; // reference to AgriSolarProject.id
    string amount;
    string expectedReturn;
    string? createdAt;
|};

// IoT / Sensor Data
type SensorReading record {|
    string? id;
    string deviceId;
    string sensorType;
    string value;
    string unit;
    int? timestamp;
|};

// User Statistics
type UserStats record {|
    string userId;
    string energyGenerated;
    string energyConsumed;
    string earnings;
    string co2Saved;
    string? lastUpdated;
|};

// ===================== AUTH SERVICE =====================
@http:ServiceConfig {
    cors: {
        allowOrigins: ["http://localhost:5173"],
        allowMethods: ["POST", "GET", "OPTIONS"],
        allowHeaders: ["Content-Type", "Authorization"]
    }
}
service /api on authListener {

    private mongodb:Database? userDb;

    function init() returns error? {
        self.userDb = check mongoDb->getDatabase("userDb");
    }

    resource function post signup(UserInput req) returns http:Response|error {
        mongodb:Collection users = check (<mongodb:Database>self.userDb)->getCollection("users");

        if req.password.length() < 8 {
            return createErrorResponse("Password must be at least 8 characters.");
        }

        stream<User, error?> dup = check users->find({
            "$or": [{username: req.username}, {email: req.email}]
        });
        User[] dupArr = check from User u in dup
            select u;
        if dupArr.length() > 0 {
            return createErrorResponse("Username or email already exists.");
        }

        string salt = uuid:createType4AsString();
        string hashed = crypto:hashSha256((req.password + salt).toBytes()).toBase16();

        User newUser = {
            id: uuid:createType4AsString(),
            username: req.username,
            password: hashed,
            salt: salt,
            email: req.email ?: "",
            resetToken: (),
            resetExpires: ()
        };

        check users->insertOne(newUser);
        return jsonMsg("Signup successful. Please proceed to login.");
    }

    resource function post login(LoginInput req) returns http:Response|error {
        mongodb:Collection users = check (<mongodb:Database>self.userDb)->getCollection("users");

        stream<User, error?> rs = check users->find({username: req.username});
        User[] hits = check from User u in rs
            select u;

        if hits.length() == 0 {
            return createErrorResponse("Invalid username or password.");
        }

        User u = hits[0];
        string hashed = crypto:hashSha256((req.password + u.salt).toBytes()).toBase16();
        if hashed != u.password {
            return createErrorResponse("Invalid username or password.");
        }

        jwt:IssuerConfig issuerConfig = {
            issuer: jwtIssuer,
            audience: [jwtAudience]
        };
        string|error token = jwt:issue(issuerConfig);
        if token is error {
            return createErrorResponse("Failed to issue token.");
        }

        http:Response r = new;
        r.setPayload({message: "Login successful!", token: token});
        return r;
    }

    resource function get profile(http:Caller caller, http:Request req) returns error? {
        string|error authHeader = req.getHeader("Authorization");
        if authHeader is error || !authHeader.startsWith("Bearer ") {
            check caller->respond({message: "Unauthorized"});
            return;
        }

        string token = authHeader.substring(7);
        jwt:ValidatorConfig validatorConfig = {issuer: jwtIssuer, audience: [jwtAudience]};
        map<anydata>|jwt:Error validated = jwt:validate(token, validatorConfig);
        if validated is map<anydata> {
            string uname = <string>validated["sub"];
            check caller->respond({message: "Welcome, " + uname});
        } else {
            check caller->respond({message: "Invalid or expired token."});
        }
    }
}

// ===================== PASSWORD SERVICE =====================
@http:ServiceConfig {
    cors: {
        allowOrigins: ["http://localhost:5173", "http://localhost:3000"],
        allowMethods: ["POST", "OPTIONS"],
        allowHeaders: ["Content-Type"]
    }
}
service /api on passwordListener {

    private mongodb:Database? userDb;

    function init() returns error? {
        self.userDb = check mongoDb->getDatabase("userDb");
    }

    resource function post forgot(ResetRequest req) returns http:Response|error {
        mongodb:Collection users = check (<mongodb:Database>self.userDb)->getCollection("users");
        stream<User, error?> s = check users->find({username: req.username, email: req.email});
        User[] found = check from User u in s
            select u;

        if found.length() == 0 {
            return createErrorResponse("User not found.");
        }

        string token = uuid:createType4AsString();
        int expiresInt = time:utcNow()[0] + 15 * 60;

        mongodb:Update updateDoc = {
            "$set": {
                "resetToken": token,
                "resetExpires": expiresInt
            }
        };

        _ = check users->updateOne({"username": req.username}, updateDoc);
        return jsonMsg("Password reset token generated. Token: " + token);
    }

    resource function post reset(ResetInput req) returns http:Response|error {
        mongodb:Collection users = check (<mongodb:Database>self.userDb)->getCollection("users");
        stream<User, error?> s = check users->find({resetToken: req.token});
        User[] hits = check from User u in s
            select u;

        if hits.length() == 0 {
            return createErrorResponse("Invalid or expired token.");
        }

        User u = hits[0];
        int now = time:utcNow()[0];
        if u.resetExpires is () || <int>u.resetExpires < now {
            return createErrorResponse("Invalid or expired token.");
        }

        if req.newPassword.length() < 8 {
            return createErrorResponse("Password must be at least 8 characters.");
        }

        string newSalt = uuid:createType4AsString();
        string newHash = crypto:hashSha256((req.newPassword + newSalt).toBytes()).toBase16();

        mongodb:Update updateDoc = {
            "$set": {"password": newHash, "salt": newSalt},
            "$unset": {"resetToken": "", "resetExpires": ""}
        };

        _ = check users->updateOne({"resetToken": req.token}, updateDoc);
        return jsonMsg("Password reset successful.");
    }
}

// ===================== SOLAR POOLS SERVICE =====================
service /solarPools on authListener {

    private mongodb:Database? db;

    function init() returns error? {
        self.db = check mongoDb->getDatabase("solar_lk");
    }

    resource function post create(SolarPool pool) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("solarPools");
        pool.id = uuid:createType4AsString();
        pool.createdAt = time:utcNow()[0].toString();
        check col->insertOne(pool);
        return jsonMsg("SolarPool created with ID: " + (pool.id ?: ""));
    }

    resource function get list() returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("solarPools");
        stream<SolarPool, error?> s = check col->find({});
        SolarPool[] pools = check from SolarPool p in s
            select p;
        http:Response r = new;
        r.setPayload(pools);
        return r;
    }

    resource function get details(string id) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("solarPools");
        stream<SolarPool, error?> s = check col->find({id: id});
        SolarPool[] hits = check from SolarPool p in s
            select p;
        if hits.length() == 0 {
            return createErrorResponse("Pool not found");
        }
        http:Response r = new;
        r.setPayload(hits[0]);
        return r;
    }

    resource function patch update(string id, SolarPool updateData) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("solarPools");
        _ = check col->updateOne({id: id}, {"$set": updateData});
        return jsonMsg("SolarPool updated: " + id);
    }

    resource function delete remove(string id) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("solarPools");
        _ = check col->deleteOne({id: id});
        return jsonMsg("SolarPool deleted: " + id);
    }
}

// ===================== AGRI SOLAR PROJECTS SERVICE =====================
service /agriProjects on authListener {

    private mongodb:Database? db;

    function init() returns error? {
        self.db = check mongoDb->getDatabase("solar_lk");
    }

    resource function post create(AgriSolarProject project) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("agriProjects");
        project.id = uuid:createType4AsString();
        project.createdAt = time:utcNow()[0].toString();
        check col->insertOne(project);
        return jsonMsg("AgriSolarProject created with ID: " + (project.id ?: ""));
    }

    resource function get list() returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("agriProjects");
        stream<AgriSolarProject, error?> s = check col->find({});
        AgriSolarProject[] projects = check from AgriSolarProject p in s
            select p;
        http:Response r = new;
        r.setPayload(projects);
        return r;
    }

    resource function get details(string id) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("agriProjects");
        stream<AgriSolarProject, error?> s = check col->find({id: id});
        AgriSolarProject[] hits = check from AgriSolarProject p in s
            select p;
        if hits.length() == 0 {
            return createErrorResponse("Project not found");
        }
        http:Response r = new;
        r.setPayload(hits[0]);
        return r;
    }

    resource function patch update(string id, AgriSolarProject updateData) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("agriProjects");
        _ = check col->updateOne({id: id}, {"$set": updateData});
        return jsonMsg("AgriSolarProject updated: " + id);
    }

    resource function delete remove(string id) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("agriProjects");
        _ = check col->deleteOne({id: id});
        return jsonMsg("AgriSolarProject deleted: " + id);
    }
}

// ===================== INVESTMENTS SERVICE =====================
service /investments on authListener {

    private mongodb:Database? db;

    function init() returns error? {
        self.db = check mongoDb->getDatabase("solar_lk");
    }

    resource function post create(Investment inv) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("investments");
        inv.id = uuid:createType4AsString();
        inv.createdAt = time:utcNow()[0].toString();
        check col->insertOne(inv);
        return jsonMsg("Investment created with ID: " + (inv.id ?: ""));
    }

    resource function get list(string? userId) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("investments");
        stream<Investment, error?> s;
        if userId is string {
            s = check col->find({userId: userId});
        } else {
            s = check col->find({});
        }
        Investment[] invs = check from Investment i in s
            select i;
        http:Response r = new;
        r.setPayload(invs);
        return r;
    }

    resource function get details(string id) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("investments");
        stream<Investment, error?> s = check col->find({id: id});
        Investment[] hits = check from Investment i in s
            select i;
        if hits.length() == 0 {
            return createErrorResponse("Investment not found");
        }
        http:Response r = new;
        r.setPayload(hits[0]);
        return r;
    }

    resource function patch update(string id, Investment updateData) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("investments");
        _ = check col->updateOne({id: id}, {"$set": updateData});
        return jsonMsg("Investment updated: " + id);
    }

    resource function delete remove(string id) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("investments");
        _ = check col->deleteOne({id: id});
        return jsonMsg("Investment deleted: " + id);
    }
}

// ===================== SENSOR / IOT SERVICE =====================
service /sensorData on authListener {

    private mongodb:Database? db;

    function init() returns error? {
        self.db = check mongoDb->getDatabase("solar_lk");
    }

    resource function post .(SensorReading reading) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("sensorData");
        reading.id = uuid:createType4AsString();
        reading.timestamp = time:utcNow()[0];
        check col->insertOne(reading);
        return jsonMsg("Sensor data recorded for device: " + reading.deviceId);
    }

    resource function get fetch(string? deviceId) returns http:Response|error {
        mongodb:Collection col = check (<mongodb:Database>self.db)->getCollection("sensorData");
        stream<SensorReading, error?> s;
        if deviceId is string {
            s = check col->find({deviceId: deviceId});
        } else {
            s = check col->find({});
        }
        SensorReading[] readings = check from SensorReading r in s
            select r;
        http:Response r = new;
        r.setPayload(readings);
        return r;
    }

    resource function get summary(string? poolId) returns http:Response|error {
        http:Response r = new;
        r.setPayload({poolId: poolId ?: "all", dailyEnergy: "123.4 kWh", monthlyEnergy: "3456.7 kWh"});
        return r;
    }
}

// ===================== DASHBOARD / USER STATS =====================
service /userStats on authListener {

    private mongodb:Database? db;

    function init() returns error? {
        self.db = check mongoDb->getDatabase("solar_lk");
    }

    resource function get stats(string userId) returns http:Response|error {
        // Placeholder: compute/aggregate stats from investments, sensorData, etc.
        UserStats stats = {
            userId: userId,
            energyGenerated: "145.2 kWh",
            energyConsumed: "98.7 kWh",
            earnings: "Rs. 2,847",
            co2Saved: "87.3 kg",
            lastUpdated: time:utcNow()[0].toString()
        };
        http:Response r = new;
        r.setPayload(stats);
        return r;
    }
}
