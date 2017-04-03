import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;

public class Converter {
	public static void main(String[] args) throws IOException {
		Scanner scanner = new Scanner(new File("rawData.csv"));
		Scanner dataScanner = null;
		int index = 0;
		List<RawData> empList = new ArrayList<>();
		
		while (scanner.hasNextLine()) {
			dataScanner = new Scanner(scanner.nextLine());
			dataScanner.useDelimiter(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
			RawData rawData = new RawData();

			while (dataScanner.hasNext()) {
				String data = dataScanner.next();
				if (index == 0){
					rawData.setDate(data);
					rawData.setLocalTime(data);
				}	
				else if (index == 1)
					rawData.setBuyBroker(data);
				else if (index == 2)
					rawData.setSellBroker(data);
				else if (index == 3)
					rawData.setVolume(data);
				else if (index == 4)
					rawData.setPrice(data);
				else if (index == 5)
					rawData.setExchangeTime(data);
				else if (index == 6)
					rawData.setSYM(data);
				else
					System.out.println("invalid data::" + data);
				index++;
			}
			index = 0;
			empList.add(rawData);
		}

		scanner.close();
		
		
		//now all data has been stored in the empList
		//we can export them into a csv file now
		//if want to improve efficiency, we can export data early when reading data
		
		/*
		PrintWriter pw = new PrintWriter(new File("tradeReport.csv"));
        StringBuilder sb = new StringBuilder();
        sb.append("Date");
        sb.append(',');
        sb.append("Local Time");
        sb.append(',');
        sb.append("Exchange Time");
        sb.append(',');
        sb.append("SYM");
        sb.append(',');
        sb.append("Price");
        sb.append(',');
        sb.append("Volumn");
        sb.append(',');
        sb.append("BuyBroker");
        sb.append(',');
        sb.append("SellBroker");
        sb.append(',');
        sb.append('\n');
        
        
        Iterator<RawData> itr = empList.iterator();
        while(itr.hasNext()){
        	RawData rawData = itr.next();
        	sb.append(rawData.getDate());
            sb.append(',');
            sb.append(rawData.getLocalTime());
            System.out.println(rawData.getLocalTime());
            sb.append(',');
            sb.append(rawData.getExchangeTime());
            sb.append(',');
            sb.append(rawData.getSYM());
            sb.append(',');
            sb.append(rawData.getPrice());
            sb.append(',');
            sb.append(rawData.getVolume());
            sb.append(',');
            sb.append(rawData.getBuyBroker());
            sb.append(',');
            sb.append(rawData.getSellBroker());
            sb.append(',');
            sb.append('\n');
        }

        pw.write(sb.toString());
        pw.close();
        */
		
		//this part do the calculations
		List<Integer> delays = new ArrayList<>();
		Iterator<RawData> itr = empList.iterator();
		int sum = 0;
		int max = 0;
		int maxIndex = 0;
		int min = 1000000;
		int minIndex = 0;
		int delayIndex = 2;			//because the first row in excel is Name
		while(itr.hasNext()){
			RawData rawData = itr.next();
			String localTime = rawData.getLocalTime();
			String exchangeTime = rawData.getExchangeTime();
			int delay = rawData.getDelay();
			delays.add(delay);
			if (delay > max){
				max = delay;
				maxIndex = delayIndex;
				//System.out.println(maxIndex);
				System.out.println("max is " + rawData.getLocalTime());
			}
			if (delay < min){
				min = delay;
				minIndex = delayIndex;
			}
			sum += delay;
			delayIndex++;
		}
		int average = sum/empList.size();
		System.out.println("average is " + String.format("%1$06d", average));
		System.out.println("max is " + String.format("%1$06d", max));
		System.out.println("max index is " + maxIndex);
		System.out.println("min is " + String.format("%1$06d", min));
		System.out.println("min index is " + minIndex);
	}
}
