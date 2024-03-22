package pt.unl.fct.di.apdc.firstwebapp.util;

public class RegisterData extends LoginData {
	
	public String confirmation;
	
	public String email;
	
	public String name;
	
	public RegisterData() {
		
	}
	
	public RegisterData(String username, String password, String confirmation, String email, String name) {
		super(username, password);
		this.confirmation = confirmation;
		this.email = email;
		this.name = name;
	}
	
	/**
	 * Method to check if the data is valid for registry.
	 * @return true if all the data fields are not null and the password and confirmation password are the same, false otherwise.
	 */
	public boolean validRegistration() {
		if ( this.username == null || this.password == null || this.confirmation == null || this.email == null ||
				this.name == null || !this.password.equals(this.confirmation) ) {
			return false;
		} else {
			return true;
		}
	}
}
