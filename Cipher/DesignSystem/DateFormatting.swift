//
//  DateFormatting.swift
//  Cipher
//

import Foundation

enum CipherDateFormatting {
    static func chatList(_ date: Date) -> String {
        let calendar = Calendar.current
        if calendar.isDateInToday(date) {
            return time.string(from: date)
        }
        if calendar.isDateInYesterday(date) {
            return String(localized: "Yesterday")
        }
        if calendar.isDate(date, equalTo: Date(), toGranularity: .weekOfYear) {
            return weekday.string(from: date)
        }
        return shortDate.string(from: date)
    }

    static func messageTime(_ date: Date) -> String {
        time.string(from: date)
    }

    static func daySeparator(_ date: Date) -> String {
        let calendar = Calendar.current
        if calendar.isDateInToday(date) { return String(localized: "Today") }
        if calendar.isDateInYesterday(date) { return String(localized: "Yesterday") }
        return mediumDate.string(from: date)
    }

    static func callDuration(_ seconds: Int) -> String {
        if seconds < 60 {
            return String(localized: "\(seconds)s")
        }
        let m = seconds / 60
        let s = seconds % 60
        if m < 60 {
            return s == 0
                ? String(localized: "\(m) min")
                : String(localized: "\(m) min \(s)s")
        }
        let h = m / 60
        let rem = m % 60
        return rem == 0
            ? String(localized: "\(h) hr")
            : String(localized: "\(h) hr \(rem) min")
    }

    /// Compact mm:ss for in-call timer and voice notes.
    static func elapsedClock(_ seconds: Int) -> String {
        let m = seconds / 60
        let s = seconds % 60
        return String(format: "%d:%02d", m, s)
    }

    private static let time: DateFormatter = {
        let f = DateFormatter()
        f.locale = .autoupdatingCurrent
        f.setLocalizedDateFormatFromTemplate("Hm")
        return f
    }()

    private static let weekday: DateFormatter = {
        let f = DateFormatter()
        f.locale = .autoupdatingCurrent
        f.setLocalizedDateFormatFromTemplate("EEE")
        return f
    }()

    private static let shortDate: DateFormatter = {
        let f = DateFormatter()
        f.locale = .autoupdatingCurrent
        f.dateStyle = .short
        f.timeStyle = .none
        return f
    }()

    private static let mediumDate: DateFormatter = {
        let f = DateFormatter()
        f.locale = .autoupdatingCurrent
        f.dateStyle = .medium
        f.timeStyle = .none
        return f
    }()
}
