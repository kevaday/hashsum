from fastai.vision import *
from classifier.bin2png import file_to_image
from torchvision import transforms

import torch
import torch.nn.functional as F

DIMENSIONS = (224, 224)
NORM = imagenet_stats  # ([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
TFMS = transforms.Compose([transforms.ToTensor(), transforms.Normalize(*NORM)])


class ImageDataset(Dataset):
    def __init__(self, data=None, tfms=TFMS):
        if not data: data = []
        self.data = list(data)
        self.tfms = tfms

    def update(self, datas: list or Tensor):
        self.data.extend(list(datas))

    def __len__(self):
        return len(self.data)

    def __getitem__(self, i):
        d = self.data[i]
        return path_to_tensor(d, tfms=self.tfms)


def path_to_tensor(path: str = None, file_obj=None, tfms=TFMS) -> Tensor:
    #assert path or file_obj, 'Must provide path or file_obj'
    #if not tfms: tfms = transforms.Compose([transforms.ToTensor()])
    if path: file_obj = open(path, 'rb')
    result = tfms(file_to_image(file_obj, dimensions=DIMENSIONS))
    file_obj.close()
    return result


def get_dataloader(batch_size) -> DataLoader:
    return DataLoader(ImageDataset(), batch_size=batch_size, shuffle=False, num_workers=0)


def save_model(path, model, model_name, loss, accuracy):
    if not os.path.exists(path):
        os.makedirs(path)

    with open(os.path.join(path, f'{model_name}_loss_{round(loss, 3)}_acc_{round(accuracy, 3)}.ckpt'), 'wb') as f:
        torch.save(model, f)


def load_model(path: str, *args, **kwargs) -> Learner:
    path = os.path.abspath(path)
    return load_learner(os.path.dirname(path), os.path.basename(path), *args, **kwargs).purge()


def get_max(outputs: Tensor) -> list:
    return [max(probabilities(o)).item() for o in outputs]


def probabilities(outputs: Tensor) -> Tensor:
    return F.softmax(outputs, dim=-1)


def output_to_class(learner: Learner, outputs: Tensor) -> List[str]:
    idx_to_class = {i: c for i, c in enumerate(learner.data.classes)}
    return [idx_to_class[torch.argmax(o, dim=-1).item()] for o in outputs]


def malware_prob(learner: Learner, outputs: Tensor) -> list:
    probs = probabilities(outputs).tolist()
    return [1 - p[{c: i for i, c in enumerate(learner.data.classes)}['Legitimate']] for p in probs]


def set_device(gpu=True):
    if gpu:
        defaults.device = torch.device('cuda:0' if torch.cuda.is_available() else 'cpu')
    else:
        defaults.device = torch.device('cpu')


def get_device():
    return defaults.device
