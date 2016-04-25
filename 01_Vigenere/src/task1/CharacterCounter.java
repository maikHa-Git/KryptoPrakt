package task1;

import java.util.ArrayList;

public class CharacterCounter implements Comparable<CharacterCounter> {
	private int character;
	private int count;

	public CharacterCounter(int character) {
		super();
		this.character = character;
		this.count=0;
	}

	public int getCharacter() {
		return character;
	}

	public void setCharacter(int character) {
		this.character = character;
	}

	public int getCount() {
		return count;
	}

	public void setCount(int count) {
		this.count = count;
	}
	public void incCount() {
		this.count++;
	}

	@Override
	public int compareTo(CharacterCounter o) {
		if (count < o.count)
			return -1;
		if (count > o.count)
			return 1;
		return 0;
	}

}
