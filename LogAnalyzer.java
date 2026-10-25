// GPT 5.6 Sol helped guide writing this code. Every line of code is written by me.
import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Scanner;

public class LogAnalyzer {

    public static void main(String[] args) throws Exception {
        int totalEvents = 0;
        int infoEvents = 0;
        int warningEvents = 0;
        int errorEvents = 0;
        int failedLogins = 0;
        int portScanEvents = 0;
        // integer variables to hold counts of different types of events
        HashMap<String, Integer> failedLoginCountsByIP = new HashMap<>();
        HashMap<String, Integer> portScanCountsByIP = new HashMap<>();
        HashSet<String> allIPs = new HashSet<>();
        //creating equivalent of a dictionary to store event counts by IP and collect unique IPs for correlation


        File logFile = new File("security_log.txt");
        Scanner scanner = new Scanner(logFile);
        // while loop to read each line of a file with scanner and then count the number of matching strings in each line of the file
        while (scanner.hasNextLine()) {
            String logLine = scanner.nextLine();
            totalEvents += 1;
        if (logLine.contains("INFO")){
            infoEvents += 1;
        }
        if (logLine.contains("WARN")){
            warningEvents += 1;
        }
        if (logLine.contains("ERROR")){
            errorEvents += 1;
        }
        if (logLine.contains("Failed login")){
            failedLogins += 1;
            String[] failedIPs = logLine.split("ip=");
            String failedIP = failedIPs[1];
            if (failedLoginCountsByIP.containsKey(failedIP)) {
               int currentCount = failedLoginCountsByIP.get(failedIP);
               currentCount += 1;
               failedLoginCountsByIP.put(failedIP, currentCount);
                // checks for a duplicate IP and adds 1 to the count on the hashmap with a matching key
            }
        else {
            failedLoginCountsByIP.put(failedIP, 1);
            //else statement setting the value in the hashmap with a key and value of 1
        }
        }
        if (logLine.contains("Port scan detected")) {
            portScanEvents += 1;
            String[] portScanIPsAndPorts = logLine.split("ip=");
            String[] portScanIPAndPort = portScanIPsAndPorts[1].split(" ");
            String portScanIP = portScanIPAndPort[0];
            if (portScanCountsByIP.containsKey(portScanIP)) {
                int currentCount = portScanCountsByIP.get(portScanIP);
                currentCount += 1;
                portScanCountsByIP.put(portScanIP, currentCount);

            }
            else {
                portScanCountsByIP.put(portScanIP, 1);
            }
            //almost identical code to failed login code above just tweaked for portscan flags
        }
            
        
        }
        scanner.close();
        System.out.println("\n=== Suspicious Port Scanners (2+ events) ===");
        for (String key : portScanCountsByIP.keySet()) {
            int scanCount = portScanCountsByIP.get(key);
            if (scanCount >= 2) {
                System.out.println("IP: " + key + " | Port Scan Events: " + scanCount);
            } //checks for port scan events where there are 2 or more associated with one IP
        }
        System.out.println("\n=== Suspicious Failed Login Sources (3+ attempts) ===");
        for (String key : failedLoginCountsByIP.keySet()) {
            int failedCount = failedLoginCountsByIP.get(key);
            if (failedCount >= 3) {
                System.out.println("IP: " + key + " | Failed Logins: " + failedCount);
            } //checks for failed login events where there are 3 or more associated with one IP
            
        }
        System.out.println("\n=== Correlated Security Alerts ===");
        allIPs.addAll(failedLoginCountsByIP.keySet());
        allIPs.addAll(portScanCountsByIP.keySet());
        //adds all ips into a hashset for comparison
        for (String key : allIPs) {

                int failedLogin = failedLoginCountsByIP.getOrDefault(key,0);
                int portScans = portScanCountsByIP.getOrDefault(key,0);
                //sets variables for line by line for loop and if statement, finds problematic IP addresses based on set rules
                if ((failedLogin >= 3 && portScans >= 2) || failedLogin >= 6 || portScans >= 4){
                    System.out.println(
                    "IP: " + key +
                    " | Failed Logins: " + failedLogin +
                    " | Port Scans: " + portScans
                    );
                }
                
            
            }
       
        
        System.out.println("\n=== Event Summary ===");
        System.out.println("Total Events: " + totalEvents);
        System.out.println("Informational Events: " + infoEvents);
        System.out.println("Warnings: " + warningEvents);
        System.out.println("Errors: " + errorEvents);
        System.out.println("Failed Login Attempts: " + failedLogins);
        System.out.println("Port Scan Events: " + portScanEvents);
        // Simple printout logic for the variables showing amounts of each events, each event together adds to totalEvents except for failedLogins as it is a separate check
    }
}