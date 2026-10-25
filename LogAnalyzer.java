// GPT 5.6 Sol helped guide writing this code. Every line of code is written by me.
import java.io.File;
import java.util.HashMap;
import java.util.Scanner;

public class LogAnalyzer {

    public static void main(String[] args) throws Exception {
        int totalEvents = 0;
        int infoEvents = 0;
        int warningEvents = 0;
        int errorEvents = 0;
        int failedLogins = 0;
        // integer variables to hold counts of different types of events
        HashMap<String, Integer> failedLoginIPs = new HashMap<>();
        //creating equivalent of a dictionary to store pairs of failed login IPs


        File logFile = new File("security_log.txt");
        Scanner scanner = new Scanner(logFile);
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
            if (failedLoginIPs.containsKey(failedIP)) {
               int currentCount = failedLoginIPs.get(failedIP);
               currentCount += 1;
               failedLoginIPs.put(failedIP, currentCount);
                // checks for a duplicate IP and adds 1 to the count on the hashmap with a matching key
            }
        else {
            failedLoginIPs.put(failedIP, 1);
            //else statement setting the value in the hashmap with a key and value of 1
        }
        }
        // while loop to read each line of a file with scanner and then count the number of matching strings in each line of the file
        }
        System.out.println("Suspicious IPs (3+ failed logins):");
        for (String key : failedLoginIPs.keySet()) {
            int failedcount = failedLoginIPs.get(key);
            if (failedcount >= 3) {
                System.out.println("IP: " + key + " has " + failedcount + " failed logins");
            }

        }
        //String logLine = "2026-10-20 08:07:42 WARN Failed login user=admin ip=10.0.0.8";
       
        
        scanner.close();
        System.out.println("Total Events: " + totalEvents);
        System.out.println("Informational Events: " + infoEvents);
        System.out.println("Warnings: " + warningEvents);
        System.out.println("Errors: " + errorEvents);
        System.out.println("Failed Login Attempts: " + failedLogins);
        // Simple printout logic for the variables showing amounts of each events, each event together adds to totalEvents except for failedLogins as it is a separate check
    }
}