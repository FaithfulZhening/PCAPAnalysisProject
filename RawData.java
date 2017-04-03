import java.text.Format;
import java.text.SimpleDateFormat;

public class RawData {
	private String localTime;
	private String exchangeTime;
	private String date;
	private String sym;
	private String price;
	private String volume;
	private String buyBroker;
	private String sellBroker;
	
	private int[] localTimeArray = new int[4];
	private int[] exchangeTimeArray = new int[4];
	private int[] delay = new int[4];
	
	private String timeDelay;
	
	public RawData(){
		
	}
	/*
	 * the input format will be like:
	 * "Sep  9, 2015 09:30:00.012004000 Eastern Summer Time"
	 */
	
	public void setLocalTime(String rawData){
		String[] splited = rawData.split("\\s+");
		this.localTime = splited[3].replace(".", ":").substring(0, splited[3].length()-3);
	}
	
	/*
	 * the input format will be like:
	 * "1441805400009007"
	 */
	public void setExchangeTime(String rawData){
		long rawTime = Long.valueOf(rawData.replace("\"", ""));
		long time = rawTime/1000000;
		String modTime = String.format("%1$06d", rawTime%1000000);
		java.util.Date hourMinuteSecond = new java.util.Date((long)time*1000);
		Format formatter = new SimpleDateFormat("HH:mm:ss");
		//strTime stores HH:mm:ss info
		String strTime = formatter.format(hourMinuteSecond);
		this.exchangeTime = strTime+ ":" + modTime;
	}
	
	/*
	 * the input format will be like:
	 * "Sep  9, 2015 09:30:00.012004000 Eastern Summer Time"
	 */
	
	public void setDate(String rawData){
		String[] splited = rawData.replaceAll(",","").replace("\"", "").split("\\s+");
		String month;
		String day;
		String year;
		//get month from raw data
		switch(splited[0]){
		
		//here I just wrote September because it is the only month in the data
		case "Jan": 
			month = "01";
			break;
		case "Sep":
			month = "09";
			break;
		default:
			month = "To be updated month";
			break;
		}
		
		//get day and year from raw data
		day = String.format("%1$02d", Integer.valueOf(splited[1]));
		year = splited[2];
		this.date = year + month + day;
	}
	/*
	 * the input format will be like:
	 * "FTP.DB.A "
	 */
	
	public void setSYM(String rawData){
		//get rid of all spaces
		this.sym = rawData.replace("\"", "").replaceAll("\\s+","");
	}
	
	/*
	 * the input format will be like:
	 * "54000000"
	 */
	public void setPrice(String rawData){
		Long price = Long.valueOf(rawData.replace("\"", ""))/1000000;
		String modPrice = String.format("%1$06d", Long.valueOf(rawData.replace("\"", ""))%1000000);
		this.price = price.toString() + "." + modPrice;
	}
	
	/*
	 * the input format will be like:
	 * "5000"
	 */
	public void setVolume(String rawData){
		this.volume = rawData.replace("\"", "");
	}
	
	/*
	 * the input format will be like:
	 * "7"
	 */
	public void setBuyBroker(String rawData){
		this.buyBroker = rawData.replace("\"", "");
	}
	
	/*
	 * the input format will be like:
	 * "70"
	 */
	public void setSellBroker(String rawData){
		this.sellBroker = rawData.replace("\"", "");
	}
	
	
	public String getLocalTime(){
		return this.localTime;
	}
	
	public String getExchangeTime(){
		return this.exchangeTime;
	}

	public String getDate(){
		return this.date;
	}
	
	public String getSYM(){
		return this.sym;
	}
	
	public String getPrice(){
		return this.price;
	}
	
	public String getVolume(){
		return this.volume;
	}
	
	public String getBuyBroker(){
		return this.buyBroker;
	}
	
	public String getSellBroker(){
		return this.sellBroker;
	}
	
	public int getDelay(){
		String[] localTime = this.localTime.split(":");
		String[] exchangeTime = this.exchangeTime.split(":");
		//store the time into an int array
		for(int i=0;i<4;i++){
			localTimeArray[i] = Integer.valueOf(localTime[i]);
			exchangeTimeArray[i] = Integer.valueOf(exchangeTime[i]);
		}
		int carry;
		//since the time is always in a format of "09:30:00:******", I would make things simple here
		//******Important,need to be updated when calculating complex time delay*********
		for(int i=3;i>0;i--){
			if (localTimeArray[i] >= exchangeTimeArray[i] ){
				delay[i] = localTimeArray[i] - exchangeTimeArray[i];
				carry = 0;
			}
			else{
				carry = 1;
			}
		}
		//System.out.println(String.format("%1$06d", delay[3]));
		timeDelay = String.format("%1$06d", delay[3]);
		return delay[3];
	}
}
