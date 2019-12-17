package com.kyiminhan.spring.helper;

import java.text.ParseException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

import org.springframework.format.Formatter;

public class LocalDateFormatter implements Formatter<LocalDate> {

	public static final String US_PATTERN = "MM/dd/yyyy";
	public static final String JP_PATTERN = "yyyy/MM/dd";
	public static final String NORMAL_PATTERN = "dd/MM/yyyy";

	@Override
	public LocalDate parse(final String text, final Locale locale) throws ParseException {
		return LocalDate.parse(text, DateTimeFormatter.ofPattern(LocalDateFormatter.getPattern(locale)));
	}

	@Override
	public String print(final LocalDate object, final Locale locale) {
		return DateTimeFormatter.ofPattern(LocalDateFormatter.getPattern(locale)).format(object);
	}

	public static String getPattern(final Locale locale) {
		return LocalDateFormatter.isUnitedStates(locale) ? LocalDateFormatter.US_PATTERN
				: LocalDateFormatter.isJapan(locale) ? LocalDateFormatter.JP_PATTERN
						: LocalDateFormatter.NORMAL_PATTERN;
	}

	private static boolean isUnitedStates(final Locale locale) {
		return Locale.US.getCountry().equals(locale.getCountry());
	}

	private static boolean isJapan(final Locale locale) {
		return Locale.JAPAN.getCountry().equals(locale.getCountry());
	}
}