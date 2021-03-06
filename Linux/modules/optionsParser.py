from huepy import bold, green, yellow
from sys import exit
from modules.benchmarks import benchmark_ubu as benchmark

# returns a list f benchmarks that matchess the options
def get_recommendations(options):
    recommendations = list()

    # to weed out scored / not scored recommendations
    if options.score != None:
        recommendations = [b for b in benchmark if b[1] == options.score]

    # to weed out recommendations based on platform
    if options.platform:
        if options.platform == 'server':
            platform = [b for b in benchmark if b[2]]
        else:
            platform = [b for b in benchmark if b[3]]
        if recommendations:
            recommendations = [p for p in platform if p in recommendations]
        else:
            recommendations = platform

    # to weed out recommendations based on Profile Level
    if options.level:
        level = [b for b in benchmark if b[2] ==
                 options.level or b[3] == options.level]
        if recommendations:
            recommendations = [l for l in level if l in recommendations]
        else:
            recommendations = level

    import re

    # to select (whitelist) recommendations based on option
    if options.include:
        include = list()
        for i in options.include:
            r = re.compile(i)
            include.extend(list(filter(r.match, [b[0] for b in benchmark])))
        if not include:
            if all(i.startswith(('1', '2', '3', '4', '5', '6')) for i in options.include):
                exit('Could not perform benchmarks on ' +
                     ' '.join(options.include) + ' with given conditions. Exiting.')
            else:
                exit('Can\'t inlcude recommendations not defined in CIS Benchmark document.\nRun ./ubu20cis -h/--help or refer to the documentation.')
        elif recommendations:
            recommendations = [r for r in recommendations if r[0] in include]
        else:
            recommendations = [b for b in benchmark if b[0] in include]

    # to remove (blacklist) recommendations based on option
    if options.exclude:
        exclude = list()
        for e in options.exclude:
            r = re.compile(e)
            exclude.extend(list(filter(r.match, [b[0] for b in benchmark])))
        if recommendations:
            recommendations = [
                r for r in recommendations if r[0] not in exclude]
        else:
            recommendations = [b for b in benchmark if b[0] not in exclude]

    if not recommendations and options.score == None and not options.platform and not options.level and not options.include and not options.exclude:
        recommendations = [b for b in benchmark]

    # returning the requested recommendations
    return recommendations


# displays the explanation necessary recommendations and exits
def disp_exp(options):
    if all(i.startswith(('1', '2', '3', '4', '5', '6')) for i in options.exp):
        options.include = options.exp
    for b in get_recommendations(options):
        if b[2]:
            profileServer = 'Level ' + str(b[2]) + ' Server'
        else:
            profileServer = 'N/A'
        if b[3]:
            profileWorkstation = 'Level ' + str(b[3]) + ' Workstation'
        else:
            profileWorkstation = 'N/A'
        exp = '{:<9}|{:<10}|{:<14}|{:<19}|'.format(
            b[0], 'Scored' if b[1] else 'Not Scored', profileServer, profileWorkstation) + b[4]
        if b[1]:
            print(bold(green(exp)))
        else:
            print(bold(yellow(exp)))
    exit()


if __name__ == "__main__":
    exit('Please run ./ubu20cis -h')
