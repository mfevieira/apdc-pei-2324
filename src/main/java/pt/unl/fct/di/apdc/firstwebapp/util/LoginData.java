package pt.unl.fct.di.apdc.firstwebapp.util;

public class LoginData {
	
	public String username;
	public String password;
	
	public LoginData() {
		
	}
	
	public LoginData(String username, String password) {
		this.username = username;
		this.password = password;
	}
	
	/**
	 * Method to check if the data is valid for registry.
	 * @return true if all the data fields are not null, false otherwise.
	 */
	public boolean validRegistration() {
		if ( this.username == null || this.password == null ) {
			return false;
		} else {
			return true;
		}
	}
}
