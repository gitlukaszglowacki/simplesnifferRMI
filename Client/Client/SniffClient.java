package Client;


import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Scanner;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import Server.IRMISniff;
import java.rmi.RMISecurityManager;
import java.util.Map;

public class SniffClient {

    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);
        int choice;
        boolean koniec = false;
        int  registryPort = 7000;
        IRMISniff server = null;
        try{
            //System.setSecurityManager(new RMISecurityManager());
            server = (IRMISniff)Naming.lookup("//localhost:"+registryPort+"/SniffServer");
            String desc = server.connect();
            System.out.println(desc);
        
            while(!koniec){
                choice = menu();
                switch(choice){
                    case 0:
                        koniec = true;
                        break;
                    case 1:
                        System.out.printf("Lacznie dane wejsciowe IP:\t%.2fMB\n", (server.dajWej() / 1048576.0));
                        break;
                    case 2:
                        System.out.printf("Lacznie dane wyjsciowe IP:\t%.2fMB\n", (server.dajWyj() / 1048576.0));
                        break;
                    case 3:
                        System.out.printf("Lacznie inne dane IP:\t%.2fMB - %d\n", (server.dajProm() / 1048576.0), server.dajProm());
                        break;
                    case 4:
                        double mb = server.dajTotal() / 1048576.0;
                        mb += server.dajMB();
                        System.out.printf("Lacznie: \t%.2f MB\n", mb);
                        break;
                    case 5:
                        System.out.println("*************");
                        System.out.println("IP wejsciowe");
                        System.out.println("*************");
                        HashMap ipwej, ilwej, ipwyj, ilwyj;
                        ipwej = server.dajIPwej();
                        ilwej = server.dajIloscwej();
                        pokaz_ipsy(ipwej, ilwej);
                        System.out.println("*************");
                        System.out.println("IP wyjsciowe");
                        System.out.println("*************");
                        pokaz_ipsy(server.dajIPwyj(), server.dajIloscwyj());                        
                        System.out.println("*************");
                        break;
                }
            }
        }
        catch(NotBoundException | MalformedURLException | RemoteException ex){
            System.out.println(ex);
        }
    }
    
    public static int menu() {
        Scanner input = new Scanner(System.in);
        System.out.printf("\n***********************************\n"
                        + "** Menu **\n"
			+ "*1. Pokaz ilosc wejsciowych danych*\n"
			+ "*2. Pokaz ilosc wyjsciowych danych*\n"
                        + "*3. Pokaz ilosc danych promiscuous*\n"
                	+ "*4. Pokaz total                   *\n"
                        + "*5. Pokaz IP                      *\n"
			+ "***********************************\n"
			+ "0. Koniec\n"
			+ "**********\n"
			+ "Twoj wybor:");
            return input.nextInt();
	}
        
    public static void pokaz_ipsy(HashMap ipsy, HashMap ilosc) {
        if (sprawdz_liste(ipsy) && sprawdz_liste(ilosc)) {
            Iterator<Map.Entry<Integer, String>> it = ipsy.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<Integer, String> ip_object = it.next();
                Integer i = (Integer)ip_object.getKey();
                //Integer il = (Integer)ilosc.get(i);
                System.out.printf("%s\n", (String)ip_object.getValue());
                //System.out.println(" * " + il + " razy");
            }
        }
    }

    private static boolean sprawdz_liste(HashMap map) {
        if (map.size() < 1) {
            return false;
        } else {
            return true;
        }
    }


}


