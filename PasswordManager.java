import java.io.*;
import java.security.SecureRandom;
import java.util.*;

public class PasswordManager {

    // Characters to use for password generation
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL_CHARACTERS = "!@#$%^&*()-_+=<>?";
    private static final String ALL_CHARACTERS = UPPERCASE + LOWERCASE + DIGITS + SPECIAL_CHARACTERS;

    private static final SecureRandom random = new SecureRandom();
    private static final String PASSWORD_FILE = "passwords.txt";

    // A list of common weak passwords to avoid (a few are included)
    private static final Set<String> COMMON_PASSWORDS = new HashSet<>(Arrays.asList(
        "123456", "password", "12345678", "qwerty", "12345", "123456789", "letmein", "football", "iloveyou", "admin"
    ));

    // Menu-driven application
    public static void main(String[] args) {
        PasswordManager pm = new PasswordManager();
        Scanner scanner = new Scanner(System.in);
        int choice;

        while (true) {
            System.out.println("======================================================");
            System.out.println("\nPassword Manager Menu:");
            System.out.println("1. Input a password for analysis");
            System.out.println("2. Generate a strong password");
            System.out.println("3. Exit");
            System.out.print("Enter your choice: ");
            choice = scanner.nextInt();
            scanner.nextLine();  // Consume newline

            switch (choice) {
                case 1:
                    System.out.print("Enter a password to analyze: ");
                    String userPassword = scanner.nextLine();//takes input as a string so that multichar can be used
                    pm.processUserPassword(userPassword);
                    break;
                case 2:
                    System.out.print("Enter the length of password it should be greater than or equal to 12 : ");
                    int x=scanner.nextInt();
                    if(x>=12){
                    String generatedPassword = pm.generatePassword(x);
                    System.out.println("Generated Strong Password: " + generatedPassword);
                    pm.savePassword(generatedPassword);}
                    else System.err.println("Opps you didnt enter number greater than or equal to 12 -_- ");
                    break;
                case 3:
                    System.out.println("Exiting the program...");
                    scanner.close();
                    return;
                default:
                    System.out.println("Invalid choice! Please choose a valid option.");
            }
            System.out.println("======================================================");
        }
    }

    // Process user-entered password
    public void processUserPassword(String password) {
        if (isPasswordInFile(password)) {
            System.out.println("Password is already used before. Try using diffrent password ");
        } else {
            String strength = analyzePasswordStrength(password);
            System.out.println("Password Strength: " + strength);

            if ("Weak".equals(strength)) {
                System.out.println("Your password is weak. A strong password will be generated for you.");
                String newPassword = generatePassword(12);
                System.out.println("Suggested Strong Password: " + newPassword);
                savePassword(newPassword);
            } else {
                savePassword(password);
            }
        }
    }

    // Generates a strong random password
    public String generatePassword(int length) {
        if (length < 12) {
            throw new IllegalArgumentException("Password length should be at least 12 characters");
        }

        StringBuilder password = new StringBuilder(length);

        // Ensure at least one character from each set
        password.append(UPPERCASE.charAt(random.nextInt(UPPERCASE.length())));
        password.append(LOWERCASE.charAt(random.nextInt(LOWERCASE.length())));
        password.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
        password.append(SPECIAL_CHARACTERS.charAt(random.nextInt(SPECIAL_CHARACTERS.length())));

        // Fill the rest with random characters from all sets
        for (int i = 4; i < length; i++) {
            password.append(ALL_CHARACTERS.charAt(random.nextInt(ALL_CHARACTERS.length())));
        }

        return shuffleString(password.toString());
    }

    // Shuffle characters in a string to ensure randomness
    private static String shuffleString(String input) {
        List<Character> characters = new ArrayList<>();
        for (char c : input.toCharArray()) {
            characters.add(c);
        }
        Collections.shuffle(characters, random);

        StringBuilder output = new StringBuilder(input.length());
        for (char c : characters) {
            output.append(c);
        }
        return output.toString();
    }

    //  password strength analys method
    public static String analyzePasswordStrength(String password) {
        int length = password.length();
        boolean hasUppercase = password.chars().anyMatch(Character::isUpperCase); //to check uppercase letters in user entered password
        boolean hasLowercase = password.chars().anyMatch(Character::isLowerCase); //similarly for lowercase
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);//for digits
        boolean hasSpecialChar = password.chars().anyMatch(c -> SPECIAL_CHARACTERS.indexOf(c) >= 0);
        boolean isCommonPassword = COMMON_PASSWORDS.contains(password.toLowerCase());
        boolean hasRepetitiveChars = containsRepetitiveCharacters(password);
        boolean isSequential = containsSequentialCharacters(password);
        boolean isDictionaryWord = isDictionaryWord(password);

        // Strong passwords must have all character types, be 12+ characters, and avoid common patterns
        if (length >= 12 && hasUppercase && hasLowercase && hasDigit && hasSpecialChar 
                && !isCommonPassword && !hasRepetitiveChars && !isSequential && !isDictionaryWord) {
            return "Strong";
        } else if (length >= 8 && hasUppercase && hasLowercase && (hasDigit || hasSpecialChar)
                && !isCommonPassword) {
            return "Medium";
        } else {
            return "Weak";
        }
    }

    // Detect repetitive characters like "aaaa" or "1111"
    private static boolean containsRepetitiveCharacters(String password) {
        return password.matches("(.)\\1{3,}");  // Detects 4 or more repetitive characters
    }

    // Detect simple sequential characters like "abcd" or "1234"
    private static boolean containsSequentialCharacters(String password) {
        return password.matches(".*(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg).*");
    }

    // Check if the password is a dictionary word (for simplicity, a basic check)
    private static boolean isDictionaryWord(String password) {
        // Basic dictionary check (expandable with a larger dictionary list)
        Set<String> simpleDictionary = new HashSet<>(Arrays.asList("apple", "banana", "computer", "password", "welcome"));
        return simpleDictionary.contains(password.toLowerCase());
    }

    // Save password to a file if it's not already stored
    public void savePassword(String password) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(PASSWORD_FILE, true))) {
            writer.write(password);
            writer.newLine();
            System.out.println("Password saved successfully.");
        } catch (IOException e) {
            System.out.println("Error saving the password: " + e.getMessage());
        }
    }

    // Check if a password already exists in the file
    public boolean isPasswordInFile(String password) {
        try (BufferedReader reader = new BufferedReader(new FileReader(PASSWORD_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.equals(password)) {
                    return true;
                }
            }
        } catch (IOException e) {
            System.out.println("Error reading the password file: " + e.getMessage());
        }
        return false;
    }
}
