ct StaticApplication {
    address public sensor;
    address public doctor=0xdd870fa1b7c4700f2bd7f44238821c26f7392148;
    mapping (address => Grades) serverData;
    
    address[] serverIds;
    
    struct Grades {
        uint splitData;
        bool Registered;
    }
    
    event ServerTransferDataEvent(uint timestamp, address from, address to);
    function StaticApplication() {
        sensor = msg.sender;
    }
    /*doctor*/
    //0xdd870fa1b7c4700f2bd7f44238821c26f7392148
    //0x1234567890123456789012345678901234567890
    /*Server 1*/
    //0x14723a09acff6d2a60dcdf7aa4aff308fddc160c
    /*Server 2*/
    //0x4b0897b0513fdc7c541b6d9d7e929c4e5364d2db
    /*Server3*/
    //0x583031d1113ad414f02576bd6afabfb302140225
    function isSensor() returns (bool) {
        return (msg.sender == sensor);
    }
    function isDoctor() returns (bool) {
        return (msg.sender == doctor);
    }
    
    function isGradesOf(address input) returns (bool) {
        return (msg.sender == input);
    }
    function putData(address serverId, uint splitdata) {
        // check permission
        // only the teacher can call this method
        if (!isSensor()) {
            throw;
        }
        
        // if it is first time registered
        if (serverData[serverId].Registered == false) {
            // then add to Ids array for tracking or iterating
            serverIds.push(serverId);
        }
        
        // put to mapping, or if it is already registered then overwrite it
        serverData[serverId] = Grades({
            //ChineseGrade: chineseGrade,
            //EnglishGrade: englishGrade,
            //MathGrade:    mathGrade,
            splitData : splitdata,
            Registered:   true
        });
    }
    function getSplitData(address serverId) returns (uint splitdata) {
        // only the student who owns these grades or the teacher can call this method
        if (!(isGradesOf(serverId) || isSensor())) {
            throw;
        }
        var theData = serverData[serverId];
        splitdata = theData.splitData;
    }
    
    function getDataSum(address serverId) returns (uint) {
        // check permission
        // only the student who owns these grades or the teacher can call this method
        if (!(isGradesOf(serverId) || isSensor())) {
            throw;
        }
        var theData = serverData[serverId];
        
        return theData.splitData;
    }
    function getAllData(address server1,address server2,address server3) returns (uint,uint,uint){
        if(!isDoctor()){
            throw;
        }
        return (serverData[server1].splitData,serverData[server2].splitData,serverData[server3].splitData);
    }
    function transInfo(address from, address to,uint ciphertext){
        if(isSensor()||isDoctor()||msg.sender!=from){
            throw;
        }
        serverData[to].splitData = serverData[to].splitData + ciphertext;
        ServerTransferDataEvent(now,from,to);
    }
    //cipher=701568775979383767184996825570540371312554485465938824847537854110230627203
    /*
    function getGradesAverage(address studentId) returns (uint) {
        // check permission
        // only the student who owns these grades or the teacher can call this method
        if (!(isGradesOf(studentId) || isSensor())) {
            throw;
        }
        
        return getGradesSum(studentId) / 3;
    }*/

    /*
    function getClassGradesAverage() returns (uint) {
        // check permission
        // only the teacher can call this method
        if (!isSensor()) {
            throw;
        }
        
        // iterate all the grades and calculate its average
        uint sum = 0;
        var studentNum = serverIds.length;
        for (var i = 0; i < studentNum; i++) {
            sum = sum + getGradesSum(serverIds[i]);
        }
        
        return (sum / studentNum) / 3;
    }*/
}

