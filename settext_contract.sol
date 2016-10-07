contract SetText {
    /* Constructor */
    string s;
    function settest(string sec) {
        s = sec;
    }
    function gettest() constant returns (string) {
        return s;
    }
}
