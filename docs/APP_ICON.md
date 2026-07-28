# Cipher App Icon

`Cipher/Assets.xcassets/AppIcon.appiconset/` holds three 1024×1024 PNGs — light, dark and
tinted. They are generated from a source image, not hand-drawn.

## Two things an iOS app icon must be, which a supplied image usually is not

- **Exactly 1024×1024.** The catalog slot declares that size; anything else is a build
  warning at best and a wrong-looking icon at worst.
- **Opaque, with no alpha channel.** App Store Connect rejects an icon that has one, and on
  a home screen a transparent region renders black rather than transparent.

The image this set was generated from (2026-07-29) had a third problem worth knowing about,
because it is easy to miss: it *looked* transparent but was not. The checkerboard was
**painted into the RGB pixels** — the alpha channel was fully opaque throughout. Shipping it
unchanged would have put a literal grey checkerboard on the home screen.

## How the current set was produced

1. Resize to 1024×1024 (Lanczos).
2. Find light, neutral pixels — `min(R,G,B) ≥ 225` and `max−min ≤ 12` — as *candidates* for
   background.
3. Label connected components and fill only those of 1000 px or more. Connectivity is what
   makes this safe: the whites of the eyes are light and neutral too, but they are small and
   enclosed. The size histogram had a clean cliff — four background regions of 4,030 to
   590,597 px, and the next largest component was 58 px.
4. Fill with white (light), `#1C1C1E` (dark), and black-plus-grayscale (tinted — iOS
   multiplies the user's tint over luminance, so the artwork must read as brightness rather
   than as colour).

Verified afterwards: 1024×1024, mode `RGB`, and a uniform background.

## If you replace it

Check all three of the above. A photographic icon also loses detail at the size it is
actually seen — roughly 60×60 pt on a home screen — and iOS masks it to a rounded square, so
anything near a corner gets clipped.

## Liquid Glass layered icon (optional polish)

Apple's **Icon Composer** (free from [Apple Design Resources](https://developer.apple.com/design/resources/))
builds true Liquid Glass multi-layer icons.

1. Download **Icon Composer**.
2. Import separate layers, keeping shapes simple and filled.
3. Preview light, dark, clear and tinted appearances.
4. Export the `.icon` package into the Xcode target (Xcode 26+).

Until then, the single-layer PNG set above ships with the app.
