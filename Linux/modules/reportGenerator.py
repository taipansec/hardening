from modules.optionsParser import get_recommendations
from reportlab.graphics.charts.piecharts import Pie
from reportlab.lib.colors import Color, darkgray
from reportlab.graphics.shapes import Drawing
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics import renderPDF
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from os.path import join
from csv import reader
from sys import exit

hardening = "/opt/hardening/Linux/"

colorPass = [76, 175, 80]
colorFail = [244, 67, 54]
colorWarn = [255, 152, 0]
colorPrimary = [53, 92, 125]
colorSecondary = [108, 91, 123]


def setInfo(pdf, ubu20cis_contents):
    pdf.setAuthor(ubu20cis_contents[-13][1])
    pdf.setCreator('ubu20cis')
    pdf.setProducer('ubu20cis')
    subject = 'Result of CIS Ubuntu Linux 20.04 LTS v1.1.0'
    pdf.setSubject(subject)
    return subject


def drawBorder(pdf):
    pdf.saveState()
    pdf.setStrokeColorRGB(colorPrimary[0]/256, colorPrimary[1]/256, colorPrimary[2]/256)
    pdf.setLineWidth(4)
    pdf.rect(A4[0]/12, A4[1]/17, A4[0]*10/12, A4[1]*15/17)
    pdf.restoreState()


def makeTitle(pdf, ubu20cis_contents, subject):
    pdf.saveState()
    # border coloring
    pdf.setFillColorRGB(colorPrimary[0]/256, colorPrimary[1]/256, colorPrimary[2]/256)
    pdf.rect(0, 0, A4[0]/12, A4[1], fill=1, stroke=0)
    pdf.rect(0, 0, A4[0], A4[1]/17, fill=1, stroke=0)
    pdf.rect(A4[0]*11/12, 0, A4[0]/12, A4[1], fill=1, stroke=0)
    pdf.rect(0, A4[1]*16/17, A4[0], A4[1]/17, fill=1, stroke=0)
    # title text
    pdf.setFillColorRGB(colorSecondary[0]/256, colorSecondary[1]/256, colorSecondary[2]/256)
    pdf.setFont('SF-Pro-Rounded-Heavy', 30)
    pdf.drawCentredString(A4[0]*4/10, A4[1]*18/50, ubu20cis_contents[-12][1])
    pdf.drawCentredString(A4[0]*6/10, A4[1]*20/50, ubu20cis_contents[-11][1])
    pdf.setFont('SF-Pro-Rounded-Bold', 15)
    # subject
    pdf.drawCentredString(A4[0]/2, A4[1]*25/50, subject)
    # passed
    pdf.drawCentredString(A4[0]/2, A4[1]*27/50, ubu20cis_contents[-2][0])
    # score
    pdf.saveState()
    score = ubu20cis_contents[-1][0].split('%')[0].split(' ')[-1]
    if int(score) > 75:
        pdf.setFillColorRGB(colorPass[0]/256, colorPass[1]/256, colorPass[2]/256)
    elif int(score) > 50:
        pdf.setFillColorRGB(colorWarn[0]/256, colorWarn[1]/256, colorWarn[2]/256)
    else:
        pdf.setFillColorRGB(colorFail[0]/256, colorFail[1]/256, colorFail[2]/256)
    pdf.drawCentredString(A4[0]/2, A4[1]*29/50, ubu20cis_contents[-1][0])
    pdf.restoreState()
    # auditor name
    if ubu20cis_contents[-13][1]:
        pdf.drawRightString(A4[0]*10/12, A4[1]*38/50, "Audit Performed by")
        pdf.saveState()
        pdf.setFont('SF-Pro-Rounded-Heavy', 25)
        pdf.drawRightString(A4[0]*10/12, A4[1]*40/50, ubu20cis_contents[-13][1])
        pdf.restoreState()
    pdf.restoreState()
    pdf.showPage()


def makePie(pdf, ubu20cis_contents, total):
    pdf.saveState()
    d = Drawing(A4[0]*6/12, A4[1]*5/17)
    pc = Pie()
    pc.x = A4[0]*4/12
    pc.y = A4[1]*5/17
    pc.width = A4[0]*4/12
    pc.height = A4[0]*4/12
    passd = len([s for s in ubu20cis_contents if len(s) > 3 and s[2] == 'PASS'])
    faild = len([s for s in ubu20cis_contents if len(s) > 3 and s[2] == 'FAIL'])
    check = len([s for s in ubu20cis_contents if len(s) > 3 and s[2] == 'CHEK'])
    excluded = total - (passd + faild + check)
    pc.data = [passd, faild, excluded, check]
    pc.simpleLabels = 0
    pc.slices.strokeWidth = 0.5
    pc.slices.fontName = 'SF-Pro-Rounded-Heavy'
    pc.slices.fontSize = 8
    pc.slices.labelRadius = 1.1
    pc.slices[0].popout = 10
    pc.slices[0].fillColor = Color(colorPass[0]/256, colorPass[1]/256, colorPass[2]/256, 1)
    pc.slices[0].fontColor = Color(colorPass[0]/256, colorPass[1]/256, colorPass[2]/256, 1)
    pc.slices[0].label_text = 'which is {:.3f}% of all tests\n{} of {} tests ({:.3f}%) Passed,'.format(
        (passd/total)*100, passd, (passd+faild+check), (passd/(passd+faild+check))*100)
    pc.slices[1].fillColor = Color(colorFail[0]/256, colorFail[1]/256, colorFail[2]/256, 1)
    pc.slices[1].fontColor = Color(colorFail[0]/256, colorFail[1]/256, colorFail[2]/256, 1)
    pc.slices[1].label_text = 'which is {:.3f}% of all tests\n{} of {} tests ({:.3f}%) Failed,'.format(
        (faild/total)*100, faild, (passd+faild+check), (faild/(passd+faild+check))*100)
    pc.slices[2].fillColor = darkgray
    pc.slices[2].fontColor = darkgray
    pc.slices[2].label_text = '{} of {} tests ({:.0f}%) Excluded'.format(
        excluded, total, (excluded/total)*100)
    pc.slices[3].fillColor = Color(colorWarn[0]/256, colorWarn[1]/256, colorWarn[2]/256, 1)
    pc.slices[3].fontColor = Color(colorWarn[0]/256, colorWarn[1]/256, colorWarn[2]/256, 1)
    pc.slices[3].label_text = 'which is {:.3f}% of all tests\n{} of {} tests ({:.3f}%) are to be Checked,'.format(
        (check/total)*100, check, (passd+faild+check), (check/(passd+faild+check))*100)
    d.add(pc)
    renderPDF.draw(d, pdf, -A4[0]/52, -A4[1]/6)
    pdf.restoreState()


def makeResult(pdf, ubu20cis_contents, total):
    drawBorder(pdf)
    makePie(pdf, ubu20cis_contents, total)
    pdf.saveState()
    pdf.setFont('SF-Pro-Rounded-Bold', 15)
    # start time utc
    pdf.drawString(3*(A4[0]/10)/2, A4[1]*4/8, ubu20cis_contents[-21][0])
    # start time local
    pdf.drawString(3*(A4[0]/10)/2, A4[1]*4/8 + 30, ubu20cis_contents[-20][0])
    # finish time utc
    pdf.drawString(3*(A4[0]/10)/2, A4[1]*4/8 + 60, ubu20cis_contents[-5][0])
    # finish time local
    pdf.drawString(3*(A4[0]/10)/2, A4[1]*4/8 + 90, ubu20cis_contents[-4][0])
    # test and time
    pdf.drawString(3*(A4[0]/10)/2, A4[1]*4/8 + 120, ubu20cis_contents[-3][0])
    pdf.restoreState()
    pdf.showPage()


def makeIntro(pdf, ubu20cis_contents):
    drawBorder(pdf)
    pdf.saveState()
    startColumn = 3*(A4[0]/10)/2
    startRow = A4[1]/8
    # auditor description
    pdf.setFont('SF-Pro-Rounded-Bold', 15)
    pdf.drawString(startColumn, startRow, 'Auditor Description')
    pdf.setFont('SF-Mono-Heavy', 11)
    index = 0
    line = 15
    for i in range(0, len(ubu20cis_contents[-10][1])):
        if ubu20cis_contents[-10][1][i] == '[' or ubu20cis_contents[-10][1][i] == ',' or ubu20cis_contents[-10][1][i] == ']' or ubu20cis_contents[-10][1][i] == "'" or ubu20cis_contents[-10][1][i] == '\\':
            continue
        elif ubu20cis_contents[-10][1][i-1] == '\\' and ubu20cis_contents[-10][1][i] == 'n':
            ''
        else:
            pdf.drawString(startColumn + 6.7*index, startRow +
                           line, ubu20cis_contents[-10][1][i])
            index += 1
        if index == 60 or ubu20cis_contents[-10][1][i-1] == '\\' and ubu20cis_contents[-10][1][i] == 'n':
            line += 15
            index = 0
        if line > 605:
            index = 0
            line = 0
            pdf.restoreState()
            pdf.showPage()
            pdf.saveState()
            drawBorder(pdf)
            pdf.setFont('SF-Mono-Heavy', 11)
    # included controls
    if line + 45 > 600:
        index = 0
        line = 0
        pdf.restoreState()
        pdf.showPage()
        pdf.saveState()
        drawBorder(pdf)
    else:
        line += 30
    pdf.setFont('SF-Pro-Rounded-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Included Controls')
    index = 0
    line += 15
    pdf.setFont('SF-Mono-Heavy', 11)
    for i in range(0, len(ubu20cis_contents[-18][1])):
        if ubu20cis_contents[-18][1][i] == '[' or ubu20cis_contents[-18][1][i] == ']' or ubu20cis_contents[-18][1][i] == "'":
            continue
        elif ubu20cis_contents[-18][1][i] != ',':
            pdf.drawString(startColumn + 6.7*index, startRow +
                           line, ubu20cis_contents[-18][1][i])
            index += 1
        if index == 60 or ubu20cis_contents[-18][1][i] == ',':
            line += 15
            index = -1
        if line > 605:
            index = 0
            line = 0
            pdf.restoreState()
            pdf.showPage()
            pdf.saveState()
            drawBorder(pdf)
            pdf.setFont('SF-Mono-Heavy', 11)
    # excluded controls
    if line + 45 > 600:
        index = 0
        line = 0
        pdf.restoreState()
        pdf.showPage()
        pdf.saveState()
        drawBorder(pdf)
    else:
        line += 30
    pdf.setFont('SF-Pro-Rounded-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Excluded Controls')
    index = 0
    line += 15
    pdf.setFont('SF-Mono-Heavy', 11)
    for i in range(0, len(ubu20cis_contents[-17][1])):
        if ubu20cis_contents[-17][1][i] == '[' or ubu20cis_contents[-17][1][i] == ']' or ubu20cis_contents[-17][1][i] == "'":
            continue
        elif ubu20cis_contents[-17][1][i] != ',':
            pdf.drawString(startColumn + 6.7*index, startRow +
                           line, ubu20cis_contents[-17][1][i])
            index += 1
        if index == 60 or ubu20cis_contents[-17][1][i] == ',':
            line += 15
            index = -1
        if line > 605:
            index = 0
            line = 0
            pdf.restoreState()
            pdf.showPage()
            pdf.saveState()
            drawBorder(pdf)
            pdf.setFont('SF-Mono-Heavy', 11)
    # Level
    if line + 135 > 600:
        index = 0
        line = 0
        pdf.restoreState()
        pdf.showPage()
        pdf.saveState()
        drawBorder(pdf)
    else:
        line += 30
    pdf.setFont('SF-Pro-Rounded-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Scoring Level')
    pdf.setFont('SF-Pro-Rounded-Bold', 12)
    pdf.drawString(startColumn + 180, startRow + line,
                   'Both Level 1 and 2' if not ubu20cis_contents[-16][1] else ubu20cis_contents[-16][1][0])
    # Score
    line += 30
    pdf.setFont('SF-Pro-Rounded-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Score')
    pdf.setFont('SF-Pro-Rounded-Bold', 12)
    if not ubu20cis_contents[-15][1]:
        pdf.drawString(startColumn + 180, startRow +
                       line, 'Both Scored and Not Scored')
    else:
        pdf.drawString(startColumn + 180, startRow + line,
                       'Scored' if ubu20cis_contents[-15][1][0] else 'Not Scored')
    # Platform
    line += 30
    pdf.setFont('SF-Pro-Rounded-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Platform')
    pdf.setFont('SF-Pro-Rounded-Bold', 12)
    pdf.drawString(startColumn + 180, startRow + line, ubu20cis_contents[-14][1])
    # Verbosity
    line += 30
    pdf.setFont('SF-Pro-Rounded-Bold', 15)
    pdf.drawString(startColumn, startRow + line, 'Verbosity')
    pdf.setFont('SF-Pro-Rounded-Bold', 12)
    pdf.drawString(startColumn + 180, startRow + line, ubu20cis_contents[-6][1])
    pdf.restoreState()
    pdf.showPage()


def makeIndex(pdf, ubu20cis_contents):
    drawBorder(pdf)
    pdf.bookmarkPage('Index')
    pdf.saveState()
    # Title -> INDEX
    pdf.setFillColorRGB(
        colorSecondary[0]/256, colorSecondary[1]/256, colorSecondary[2]/256)
    pdf.setFont('SF-Pro-Rounded-Heavy', 20)
    pdf.drawCentredString(A4[0]/2, A4[1]/8, 'Index of Results')
    pdf.restoreState()
    # Index
    pdf.setFont('SF-Mono-Heavy', 11)
    line = 150
    for row in range(1, len(ubu20cis_contents)-24):
        pdf.saveState()
        if ubu20cis_contents[row][2] == 'PASS':
            pdf.setFillColorRGB(
                colorPass[0]/256, colorPass[1]/256, colorPass[2]/256)
        elif ubu20cis_contents[row][2] == 'FAIL':
            pdf.setFillColorRGB(
                colorFail[0]/256, colorFail[1]/256, colorFail[2]/256)
        elif ubu20cis_contents[row][2] == 'CHEK':
            pdf.setFillColorRGB(
                colorWarn[0]/256, colorWarn[1]/256, colorWarn[2]/256)
        # recommendation number
        pdf.drawCentredString(3*(A4[0]/10)/2, line, ubu20cis_contents[row][0])
        # message
        pdf.drawString(A4[0]*5/20, line, ubu20cis_contents[row][1])
        pdf.linkRect(ubu20cis_contents[row][0], ubu20cis_contents[row][0], (A4[0]*5/20, A4[1] -
                                                                      line - 2, A4[0]*5/20 + 6.7*len(ubu20cis_contents[row][1]), A4[1] - line + 8), relative=1)
        # result
        pdf.drawCentredString(A4[0]*17/20, line, ubu20cis_contents[row][2])
        line += 20
        if line > 770 and ((row + 1) != (len(ubu20cis_contents)-24)):
            line = 100
            pdf.restoreState()
            pdf.showPage()
            pdf.saveState()
            drawBorder(pdf)
            pdf.setFont('SF-Mono-Heavy', 11)
            continue
        pdf.restoreState()
    pdf.showPage()


def makeBody(pdf, ubu20cis_contents, recommendations):
    for i, row in enumerate(range(1, len(ubu20cis_contents)-24)):
        drawBorder(pdf)
        pdf.bookmarkPage(ubu20cis_contents[row][0])
        pdf.saveState()
        # Recommendation number and explanation
        pdf.setFillColorRGB(
            colorSecondary[0]/256, colorSecondary[1]/256, colorSecondary[2]/256)
        pdf.setFont('SF-Pro-Rounded-Heavy', 15)
        pdf.drawCentredString(A4[0]/2, A4[1]/8, ubu20cis_contents[row][0])
        if len(recommendations[i][4]) < 60:
            pdf.drawCentredString(A4[0]/2, A4[1]/8 + 20, recommendations[i][4])
        elif len(recommendations[i][4]) < 85:
            pdf.setFont('SF-Pro-Rounded-Heavy', 10)
            pdf.drawCentredString(A4[0]/2, A4[1]/8 + 20, recommendations[i][4])
        else:
            pdf.setFont('SF-Pro-Rounded-Heavy', 10)
            pdf.drawCentredString(A4[0]/2, A4[1]/8 + 20, recommendations[i][4])
        startColumn = 3*(A4[0]/10)/2
        startRow = 250
        # Scored
        pdf.setFont('SF-Pro-Rounded-Bold', 15)
        pdf.drawString(
            startColumn, A4[1]/8 + 50, 'Scored' if recommendations[i][1] else 'Not Scored')
        # Server Level
        if recommendations[i][2]:
            profileServer = 'Level ' + \
                str(recommendations[i][2]) + ' Server'
        else:
            profileServer = 'N/A'
        pdf.drawString(startColumn, A4[1]/8 + 70, profileServer)
        # Workstation Level
        if recommendations[i][3]:
            profileWorkstation = 'Level ' + \
                str(recommendations[i][3]) + ' Workstation'
        else:
            profileWorkstation = 'N/A'
        pdf.drawString(startColumn, A4[1]/8 + 90, profileWorkstation)
        pdf.restoreState()
        pdf.saveState()
        # result
        pdf.setFont('SF-Pro-Rounded-Bold', 13)
        pdf.drawString(startColumn, startRow, 'Result')
        pdf.setFont('Times-Roman', 12)
        if ubu20cis_contents[row][2] == 'PASS':
            pdf.setFillColorRGB(
                colorPass[0]/256, colorPass[1]/256, colorPass[2]/256)
        elif ubu20cis_contents[row][2] == 'FAIL':
            pdf.setFillColorRGB(
                colorFail[0]/256, colorFail[1]/256, colorFail[2]/256)
        elif ubu20cis_contents[row][2] == 'CHEK':
            pdf.setFillColorRGB(
                colorWarn[0]/256, colorWarn[1]/256, colorWarn[2]/256)
        pdf.drawString(7*(A4[0]/10)/2, startRow, ubu20cis_contents[row][2])
        pdf.restoreState()
        pdf.saveState()
        # Message
        pdf.setFont('SF-Pro-Rounded-Bold', 13)
        startRow += 30
        pdf.drawString(startColumn, startRow, 'Message')
        pdf.setFont('Times-Roman', 12)
        pdf.drawString(7*(A4[0]/10)/2, startRow, ubu20cis_contents[row][1])
        # Time Taken
        pdf.setFont('SF-Pro-Rounded-Bold', 13)
        startRow += 30
        pdf.drawString(startColumn, startRow, 'Time Taken')
        pdf.setFont('Times-Roman', 12)
        if float(ubu20cis_contents[row][4]) > 1.0:
            pdf.setFillColorRGB(
                colorFail[0]/256, colorFail[1]/256, colorFail[2]/256)
        elif float(ubu20cis_contents[row][4]) > 0.01:
            pdf.setFillColorRGB(
                colorWarn[0]/256, colorWarn[1]/256, colorWarn[2]/256)
        else:
            pdf.setFillColorRGB(
                colorPass[0]/256, colorPass[1]/256, colorPass[2]/256)
        pdf.drawString(7*(A4[0]/10)/2, startRow,
                       ubu20cis_contents[row][4] + ' seconds')
        pdf.restoreState()
        pdf.saveState()
        # explanation
        pdf.setFont('SF-Pro-Rounded-Bold', 13)
        startRow += 30
        pdf.drawString(startColumn, startRow, 'Explanation:')
        pdf.setFont('SF-Mono-Heavy', 11)
        index = 0
        startRow += 25
        for l in ubu20cis_contents[row][3]:
            if l == '\n':
                startRow += 20
                index = 0
            elif l == '\t':
                index += 5
            else:
                pdf.drawString(startColumn + 6.7*index, startRow, l)
                index += 1
            if index == 65 or l == '\n':
                startRow += 15
                index = 0
            if startRow > 770:
                startRow = 100
                index = 0
                pdf.restoreState()
                pdf.showPage()
                pdf.saveState()
                drawBorder(pdf)
                pdf.setFont('SF-Mono-Heavy', 11)
        pdf.restoreState()
        pdf.showPage()


def makeOutline(pdf, ubu20cis_contents):
    pdf.addOutlineEntry('Index', 'Index')
    for row in range(1, len(ubu20cis_contents)-24):
        pdf.addOutlineEntry(
            ubu20cis_contents[row][0] + ' - ' + ubu20cis_contents[row][1], ubu20cis_contents[row][0])


def createPDF(ubu20cis):
    ubu20cis_contents = list()
    with open(ubu20cis, 'r', newline='') as f:
        csv_reader = reader(f, dialect='excel')
        for row in csv_reader:
            ubu20cis_contents.append(row)

    class Options:
        def __init__(self, dist, score, platform, level, include, exclude):
            self.dist = dist
            self.score = score
            self.platform = platform
            self.level = level
            self.include = include
            self.exclude = exclude

    from re import sub
    option = Options(
        dist=ubu20cis_contents[-9][1],
        score=None if not ubu20cis_contents[-15][1] else int(
            ubu20cis_contents[-15][1][0]),
        platform=None if not ubu20cis_contents[-14][1] else ubu20cis_contents[-14][1],
        level=None if not ubu20cis_contents[-16][1] else int(
            ubu20cis_contents[-16][1][0]),
        include=None if not ubu20cis_contents[-18][1] else sub(
            r'\[|\]| |\'', '', ubu20cis_contents[-18][1]).split(','),
        exclude=None if not ubu20cis_contents[-17][1] else sub(
            r'\[|\]| |\'', '', ubu20cis_contents[-17][1]).split(',')
    )
    recommendations = get_recommendations(option)

    pdfmetrics.registerFont(
        TTFont('SF-Mono-Heavy', join(hardening, 'fonts/SF-Mono-Heavy.ttf')))
    pdfmetrics.registerFont(
        TTFont('SF-Pro-Rounded-Bold', join(hardening, 'fonts/SF-Pro-Rounded-Bold.ttf')))
    pdfmetrics.registerFont(TTFont(
        'SF-Pro-Rounded-Heavy', join(hardening, 'fonts/SF-Pro-Rounded-Heavy.ttf')))

    pdf = canvas.Canvas(ubu20cis.split('.csv')[
                        0] + '.pdf', pagesize=A4, bottomup=0, pageCompression=1)
    pdf.setTitle(ubu20cis.split('.ubu20cis.csv')[0])
    makeTitle(pdf, ubu20cis_contents, setInfo(pdf, ubu20cis_contents))
    makeResult(pdf, ubu20cis_contents, len(get_recommendations(Options(
        dist=ubu20cis_contents[-9][1], score=None, platform=None, level=None, include=None, exclude=None))))
    makeIntro(pdf, ubu20cis_contents)
    makeOutline(pdf, ubu20cis_contents)
    makeIndex(pdf, ubu20cis_contents)
    makeBody(pdf, ubu20cis_contents, recommendations)
    pdf.save()


def generatePDF(ubu20cis):

    def forThread(file_name):
        print('\nGenerating ' + file_name.split('.csv')[0] + '.pdf')
        createPDF(file_name)
        print('\nGenerated ' + file_name.split('.csv')[0] + '.pdf')

    from glob import glob
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor() as executor:
        executor.map(forThread, glob(ubu20cis + '.ubu20cis.csv'))

    exit()


if __name__ == "__main__":
    exit('Please run ./ubu20cis -h')
