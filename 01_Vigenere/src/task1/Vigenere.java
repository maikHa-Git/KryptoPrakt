package task1;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Random;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;

import org.omg.CORBA.INTERNAL;

import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils.Collections;

import de.tubs.cs.iti.jcrypt.chiffre.Cipher;
import de.tubs.cs.iti.jcrypt.chiffre.FrequencyTables;
import de.tubs.cs.iti.jcrypt.chiffre.NGram;


public class Vigenere extends Cipher {

	private Integer key[];

	private static int ggt(int zahl1, int zahl2) {
		while (zahl2 != 0) {
			if (zahl1 > zahl2) {
				zahl1 = zahl1 - zahl2;
			} else {
				zahl2 = zahl2 - zahl1;
			}
		}
		return zahl1;
	}

	public int getInteger(BufferedReader standardInput, String message) {
		int value = -1;
		boolean accect = true;
		do {
			accect = true;
			System.out.println(message);
			try {
				value = Integer.parseInt(standardInput.readLine());
				if (value <= 0) {
					throw new RuntimeException("Die Zahl muss größer als 0 sein.");
				}
			} catch (NumberFormatException e) {
				e.printStackTrace();
				System.err.println(e.getMessage());
				accect = false;
			} catch (IOException e) {
				accect = false;
				e.printStackTrace();
				System.err.println(e.getMessage());
				System.exit(1);
			} catch (RuntimeException e) {
				accect = false;
				System.err.println(e.getMessage());
				e.printStackTrace();
			}
		} while (!accect);
		return value;
	}

	public Integer[] searchPeriodeSize(int subStrLength, int maxSize, int k, StringBuffer buffer) {

		Set<Integer> set = new LinkedHashSet<Integer>();
		for (int i = 0; i < buffer.length() - subStrLength && set.size() < maxSize; i++) {
			String search = buffer.substring(i, i + subStrLength);
			buffer.indexOf(search, i + 1);
			int pos = i;
			while ((pos = buffer.indexOf(search, pos + 1)) != -1 && set.size() < maxSize) {
				set.add((pos - i));
			}
		}
		ArrayList<Integer> setTmp = new ArrayList<>(set);
		set.clear();
		java.util.Collections.sort(setTmp);
		Random r = new Random();
		int d = setTmp.get(setTmp.size() - 1);
		for (int i = 0; i < k; i++) {
			int i1 = r.nextInt(setTmp.size() - 1);
			int i2 = r.nextInt(setTmp.size() - 1);
			int value = ggt(setTmp.get(i1), setTmp.get(i2));
			if (value > 1) {
				set.add(value);
			}
		}
		setTmp.clear();

		ArrayList<Integer> filter = new ArrayList<Integer>(set);
		java.util.Collections.sort(filter);

		for (int i = 0; i < filter.size(); i++) {
			for (int j = i + 1; j < filter.size(); j++) {
				if (filter.get(j) % filter.get(i) == 0) {
					setTmp.add(filter.get(j));
				}
			}
		}
		filter.removeAll(setTmp);
		return filter.toArray(new Integer[filter.size()]);
	}


	public void breakCipher(BufferedReader ciphertext, BufferedWriter cleartext) {
		int character;
		int number = 0;
		ArrayList<NGram> nGrams = FrequencyTables.getNGramsAsList(1, charMap);
		StringBuffer buffer = new StringBuffer();
		try {
			while ((character = ciphertext.read()) != -1) {
				number++;
				buffer.append(((char) (character)));
			}
			ciphertext.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		int subStrLength = 5;
		int maxSize = 128;
		int k = 50;

		boolean accect = true;
		BufferedReader standardInput = launcher.openStandardInput();

		subStrLength = getInteger(standardInput, "Bitte geben Sie die zu suchende Länge des Strings an:");
		maxSize = getInteger(standardInput, "Bitte geben Sie eine Schranke für die Größe des Speichers ein:");
		k = getInteger(standardInput, "Bitte geben Sie eine Schranke für die Anzahl der Iterationen an:");

		Integer[] d = searchPeriodeSize(subStrLength, maxSize, k, buffer);
		int dPeriod = 1;
		if (d.length > 1) {
			for (int i = 0; i < d.length; i++) {
				System.out.println("Mögliche Periodenlänge " + i + " " + d[i]);
			}
		} else if (d.length == 1) {
			dPeriod = d[0];
			System.out.println("Mögliche Periodenlänge " + d[0]);
		} else {
			System.err.println("Es konnte keine Periode der Länge " + 10 + " gefunden werden");
			System.exit(1);
		}
		dPeriod = getInteger(standardInput, "Bitte geben die Periodenlänge ein:");

		CharacterCounter quantities[][] = new CharacterCounter[dPeriod][modulus];
		int maxPosition[] = new int[dPeriod];

		String text = buffer.toString();

		for (int i = 0; i < dPeriod; i++) {
			for (int j = 0; j < modulus; j++) {
				quantities[i][j] = new CharacterCounter(j);
			}
		}

		for (int i = 0; i < text.length(); i++) {
			quantities[i % dPeriod][charMap.mapChar(text.charAt(i))].incCount();
		}

		for (int i = 0; i < dPeriod; i++) {
			Arrays.sort(quantities[i]);
		}

		key = new Integer[dPeriod];

		for (int i = 0; i < dPeriod; i++) {
			int mostFrequented = quantities[i][modulus - 1].getCharacter();
			int computedShift = mostFrequented - charMap.mapChar(Integer.parseInt(nGrams.get(0).getIntegers()));
			if (computedShift < 0) {
				computedShift += modulus;
			}

			key[i] = computedShift;
			System.out.println("Schlüssel k_" + i + " " + key[i] + " folgt aus den Vorschlag, dass Chiffrenbuchstabe "
					+ (char) charMap.remapChar(quantities[i][modulus - 1].getCharacter()) + " dem KlartexBuchstaben "
					+ nGrams.get(0).getCharacters() + " entspricht.");

		}
	}

	public void decipher(BufferedReader ciphertext, BufferedWriter cleartext) {
		int character;
		boolean characterSkipped = false;
		try {
			int i = 0;
			while ((character = ciphertext.read()) != -1) {
				character = charMap.mapChar(character);
				if (character != -1) {
					character = (character - this.key[i] + modulus) % modulus;
					character = charMap.remapChar(character);
					cleartext.write(character);
					i = (i + 1) % this.key.length;
				} else {
					characterSkipped = true;
				}
			}
			if (characterSkipped) {
				System.out.println("Warnung: Mindestens ein Zeichen aus der "
						+ "Klartextdatei ist im Alphabet nicht\nenthalten und wurde " + "überlesen.");
			}
			cleartext.close();
			ciphertext.close();
		} catch (IOException e) {
			System.err.println("Abbruch: Fehler beim Zugriff auf Klar- oder " + "Chiffretextdatei.");
			e.printStackTrace();
			System.exit(1);
		}
	}


	public void encipher(BufferedReader cleartext, BufferedWriter ciphertext) {
		int character;
		boolean characterSkipped = false;
		try {
			int i = 0;
			while ((character = cleartext.read()) != -1) {
				character = charMap.mapChar(character);
				if (character != -1) {
					character = (character + this.key[i]) % modulus;
					character = charMap.remapChar(character);
					ciphertext.write(character);
					i = (i + 1) % this.key.length;
				} else {
					characterSkipped = true;
				}
			}
			if (characterSkipped) {
				System.out.println("Warnung: Mindestens ein Zeichen aus der "
						+ "Klartextdatei ist im Alphabet nicht\nenthalten und wurde " + "überlesen.");
			}
			cleartext.close();
			ciphertext.close();
		} catch (IOException e) {
			System.err.println("Abbruch: Fehler beim Zugriff auf Klar- oder " + "Chiffretextdatei.");
			e.printStackTrace();
			System.exit(1);
		}
	}


	public void makeKey() {
		BufferedReader standardInput = launcher.openStandardInput();
		boolean accept = true;
		do {
			accept = true;
			System.out.print("Geben Sie den Modulus ein: ");
			try {
				modulus = Integer.parseInt(standardInput.readLine());
				if (modulus <= 1) {
					throw new IllegalAccessError("Modulos muss größer als 1 sein.");
				}
			} catch (NumberFormatException e) {
				System.out.println("Fehler beim Parsen der Verschiebung. Bitte " + "korrigieren Sie Ihre Eingabe.");
				accept = false;
			} catch (IOException e) {
				System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
				e.printStackTrace();
				System.exit(1);
			} catch (IllegalAccessError e) {
				e.printStackTrace();
				System.err.println(e.getMessage());
				accept = false;
			}
		} while (!accept);

		do {
			accept = true;
			System.out.print("Geben Sie den Schlüssel: ");
			try {
				StringTokenizer st = new StringTokenizer(standardInput.readLine(), " ");
				ArrayList<Integer> keys = new ArrayList();
				int i = 0;
				while (st.hasMoreTokens()) {
					int value = Integer.parseInt(st.nextToken());
					if (value <= 1 || value >= modulus) {
						throw new IllegalAccessError("Die Werte müssen zwischen 1 und Modulos liegen.");
					}
					keys.add(value);
				}
				this.key = keys.toArray(new Integer[keys.size()]);
				System.out.println(this.key);
			} catch (NumberFormatException e) {
				System.out.println("Fehler beim Parsen der Verschiebung. Bitte " + "korrigieren Sie Ihre Eingabe.");
				accept = false;
			} catch (IOException e) {
				System.err.println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
				e.printStackTrace();
				System.exit(1);
			} catch (IllegalAccessError e) {
				e.printStackTrace();
				System.err.println(e.getMessage());
				accept = false;
			}
		} while (!accept);

	}

	public void readKey(BufferedReader key) {
		try {
			StringTokenizer st = new StringTokenizer(key.readLine(), " ");
			modulus = Integer.parseInt(st.nextToken());
			System.out.println("Modulus: " + modulus);
			ArrayList<Integer> keys = new ArrayList();
			int i = 0;
			while (st.hasMoreTokens()) {
				int value = Integer.parseInt(st.nextToken());
				keys.add(value);
				System.out.println("Schlüssel " + i + ": " + value);
			}
			this.key = (Integer[]) keys.toArray(new Integer[keys.size()]);
		} catch (IOException e) {
			System.err.println("Abbruch: Fehler beim Lesen oder Schließen der " + "Schlüsseldatei.");
			e.printStackTrace();
			System.exit(1);
		} catch (NumberFormatException e) {
			System.err.println("Abbruch: Fehler beim Parsen eines Wertes aus der " + "Schlüsseldatei.");
			e.printStackTrace();
			System.exit(1);
		}
	}

	public void writeKey(BufferedWriter key) {
		try {
			key.write(modulus + " ");
			int i = 0;
			for (; i < this.key.length - 1; i++) {
				key.write(this.key[i] + " ");
			}
			key.write(this.key[i] + "");
			key.newLine();
			key.close();
		} catch (IOException e) {
			System.out.println("Abbruch: Fehler beim Schreiben oder Schließen der " + "Schlüsseldatei.");
			e.printStackTrace();
			System.exit(1);
		}
	}
}
