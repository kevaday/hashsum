from PIL import Image
import math
from io import StringIO
import os
import sys


def choose_file_dimensions(infile, input_dimensions=None):
    if input_dimensions is not None and len(input_dimensions) >= 2 and input_dimensions[0] is not None and \
            input_dimensions[1] is not None:
        # the dimensions were already fully specified
        return input_dimensions
    num_bytes = int(file_size(infile))
    print("File size:", num_bytes)
    num_pixels = int(math.ceil(float(num_bytes) / 3.0))
    sqrt = math.sqrt(num_pixels)
    sqrt_max = int(math.ceil(sqrt))

    if input_dimensions is not None and len(input_dimensions) >= 1:
        if input_dimensions[0] is not None:
            # the width is specified but the height is not
            if num_pixels % input_dimensions[0] == 0:
                return input_dimensions[0], num_pixels // input_dimensions[0]
            else:
                return input_dimensions[0], num_pixels // input_dimensions[0] + 1
        else:
            # the height is specified but the width is not
            if num_pixels % input_dimensions[1] == 0:
                return num_pixels // input_dimensions[1], input_dimensions[1]
            else:
                return num_pixels // input_dimensions[1] + 1, input_dimensions[1]

    best_dimensions = None
    best_extra_bytes = None
    for i in range(int(sqrt_max), 0, -1):
        is_perfect = num_pixels % i == 0
        if is_perfect:
            dimensions = (i, num_pixels // i)
        else:
            dimensions = (i, num_pixels // i + 1)
        extra_bytes = dimensions[0] * dimensions[1] * 3 - num_bytes
        if dimensions[0] * dimensions[1] >= num_pixels and (best_dimensions is None or extra_bytes < best_extra_bytes):
            best_dimensions = dimensions
            best_extra_bytes = extra_bytes
        if is_perfect:
            break
    if best_extra_bytes > 0:
        sys.stderr.write(
            "Could not find PNG dimensions that perfectly encode %s bytes; the encoding will be tail-padded with %s "
            "zeros.\n" % (num_bytes, best_extra_bytes))
    return best_dimensions


def file_to_image(f, dimensions=None) -> Image:
    dimensions = choose_file_dimensions(f.name, dimensions)
    # print("Dimensions:", dimensions)
    img = Image.new('RGB', dimensions)
    pixels = img.load()
    row = 0
    column = -1

    while True:
        b = f.read(3)
        if not b:
            break

        column += 1
        if column >= img.size[0]:
            column = 0
            row += 1
            if row >= img.size[1]:
                break
            #    raise ValueError(f"Failed to convert file {infile}")
        # print("b[0]:", b[0], " b[1]:",b[1], " b[2]", b[2])
        color = [b[0], 0, 0]
        if len(b) > 1:
            color[1] = b[1]
        if len(b) > 2:
            color[2] = b[2]

        pixels[column, row] = tuple(color)

    return img


def file_to_png(infile, outfile, dimensions=None):
    with open(infile, 'rb') as f:
        img = file_to_image(f, dimensions=dimensions)

    img.save(outfile, format="PNG")


def png_to_file(infile, outfile):
    img = Image.open(infile)
    rgb_im = img.convert('RGB')
    for row in range(img.size[1]):
        for col in range(img.size[0]):
            r, g, b = rgb_im.getpixel((col, row))
            outfile.write(chr(r))
            outfile.write(chr(g))
            outfile.write(chr(b))


def file_size(fname):
    import os
    statinfo = os.stat(fname)
    return statinfo.st_size


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="A simple cross-platform script for encoding any binary file into a lossless PNG.", prog="bin2png")

    parser.add_argument('-f', "--infile", default='',
                        help="the file to encode as a PNG (defaults to '-', which is stdin)")
    parser.add_argument("-o", "--outfile", default='out.png', help="the output file (defaults to '-', which is stdout)")
    parser.add_argument("-d", "--decode", action="store_true", default=False,
                        help="decodes the input PNG back to a file")
    parser.add_argument("-w", "--width", type=int, default=None, help="constrain the output PNG to a specific width")
    parser.add_argument("-v", "--height", type=int, default=None, help="constrain the output PNG to a specific height")

    args = parser.parse_args()

    if args.decode:
        png_to_file(args.infile, args.outfile)
    else:
        dimensions = None
        if args.height is not None or args.width is not None:
            dimensions = (args.width, args.height)
        print("Input file:{}".format(args.infile))
        print("Output file:{}".format(args.outfile))
        file_to_png(args.infile, args.outfile, dimensions=dimensions)
