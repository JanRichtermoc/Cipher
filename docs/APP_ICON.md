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

Regenerated 2026-07-29 from `Finalikona.png` — a speech-bubble-shaped photograph on a white
field.

That source arrived in better shape than the previous one: already exactly 1024×1024, already
mode `RGB` with no alpha channel, and with a genuinely uniform pure-white border rather than a
painted checkerboard. Checked before anything else, because the previous source looked
transparent and was not (see above), and "it looks fine" is not a property of a file.

Two measurements decided the rest:

- **Nothing is clipped.** iOS masks the icon to a superellipse. Approximating Apple's with
  exponent 5 and testing every non-white pixel against it gives **zero** outside the mask,
  despite a left margin of only 26 px. The bubble survives the mask intact.
- **Near-white is not the same as background.** 49.8% of the canvas is the white field, but
  **182 near-white pixels sit inside the artwork** — bright highlights on the face and in the
  photo's own background. Replacing every white pixel would have punched 182 holes through it.

So the background is found by flood fill from the border through near-white (`≥ 245` in all
channels), exactly as for the previous icon and for the same reason: connectivity is what
distinguishes "the surrounding canvas" from "a bright part of the picture".

The three variants:

| File | Background | Artwork |
|---|---|---|
| `AppIcon.png` | white, untouched | pixel-identical to the source |
| `AppIcon-dark.png` | `#1C1C1E` | untouched |
| `AppIcon-tinted.png` | black | grayscale (Rec. 709 luminance) |

Tinted is grayscale on black because iOS multiplies the user's tint over luminance: the
artwork has to read as brightness rather than as colour, and a non-black background would let
the tint flood the whole square.

Each output is verified after writing — 1024×1024, mode `RGB`, no alpha band, and a
single-colour border that matches the intended background.

**The source file is not kept separately.** `AppIcon.png` is pixel-identical to it (asserted,
not assumed), so a second copy would be the same bytes under a different name and one more
thing to keep in step.

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
